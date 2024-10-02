package org.example.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.Base64;
import java.lang.IllegalStateException;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.apache.sshd.client.session.ClientSession;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.Transport;
import org.eclipse.jgit.transport.sshd.SshdSessionFactory;
import org.eclipse.jgit.transport.sshd.SshdSessionFactoryBuilder;
import org.eclipse.jgit.util.FS;

public class SshService {
	
	private TransportConfigCallback transportConfigCallback;
	private SshClient sshClient;
	private SshdSessionFactory sshdSessionFactory = null;
	private File configFile;
	
	private String privKeyPath;
	private String pubKeyPath;
	private KeyPair keyPair;
	
	@SuppressWarnings("unused")
	public SshService() {
		
		// Configure the SshClient with default client identity
        this.sshClient = SshClient.setUpDefaultClient();
        this.sshClient.setClientIdentityLoader(ClientIdentityLoader.DEFAULT);
        this.sshClient.start();

        // Create a new SshdSessionFactory using the .ssh directory
        File defaultSshDir = new File(FS.DETECTED.userHome(), "/.ssh");
        this.sshdSessionFactory = new SshdSessionFactoryBuilder()
                .setPreferredAuthentications("publickey")
                .setHomeDirectory(FS.DETECTED.userHome())
                .setSshDirectory(defaultSshDir)
                .build(null);

        // Ensure the session factory is not null before using it
        if (this.sshdSessionFactory == null) {
            throw new IllegalStateException("SSH session factory is null.");
        } 
        
        // Configure the transport to use the custom SshdSessionFactory
        this.transportConfigCallback = new TransportConfigCallback() {
            @Override
            public void configure(Transport transport) {
                if (transport instanceof SshTransport) {
                    ((SshTransport) transport).setSshSessionFactory(sshdSessionFactory);
                }
            }
        };
	}
	
	// Constructor for loading public/private key pair
	@SuppressWarnings("unused")
	public SshService(String publicKeyPath, String privateKeyPath) throws IOException{
		
	    // Set up SSH client
	    this.sshClient = SshClient.setUpDefaultClient();
	    this.sshClient.setClientIdentityLoader(ClientIdentityLoader.DEFAULT);
	    this.sshClient.start();
	    
	    this.pubKeyPath = publicKeyPath;
	    this.privKeyPath = privateKeyPath;
	    
	    // NEED TO --> SshdSessionFactoryBuilder.setDefaultKeysProvider(Function<File, Iterable<KeyPair>>);
        this.sshdSessionFactory = getSshSessionFactory();

	    // Ensure the session factory is not null before using it
	    if (this.sshdSessionFactory == null) {
	    	throw new IllegalStateException("SSH session factory is null.");
	    }

	    this.transportConfigCallback = new TransportConfigCallback() {
            @Override
            public void configure(Transport transport) {
                if (transport instanceof SshTransport) {
                    ((SshTransport) transport).setSshSessionFactory(sshdSessionFactory);
                }
            }
        };
	}
	
	// Returns necessary information for Git commands that require SSH verification
	public TransportConfigCallback getTransportConfigCallback() {
		return transportConfigCallback;
	}
	
	public SshdSessionFactory getSshSessionFactory() throws IOException {
		//Security.addProvider(new BouncyCastleProvider());		
		File defaultSshDir = new File(FS.DETECTED.userHome(), "/.ssh");
		
		createConfigFile(defaultSshDir);
		
        SshdSessionFactory sshdSession = new SshdSessionFactoryBuilder()
                .setPreferredAuthentications("publickey")
                .setHomeDirectory(FS.DETECTED.userHome())
                .setSshDirectory(defaultSshDir)
                .setDefaultKeysProvider(this::createKeyPairSafely)
                .build(null);
        
        return sshdSession;
	}
	
	private Iterable<KeyPair> createKeyPairSafely(File f) {
		Iterable<KeyPair> safePair = null;
		try {
	        safePair = createKeyPair(f);
	    } catch (Exception e) {}
	    if (safePair == null)
	    	throw new IllegalStateException("Failed to create key pair");
	    return safePair;
	}
	
	private Iterable<KeyPair> createKeyPair(File f) throws Exception{
		//System.out.println("Called createKeys method...\n");
		
		List<KeyPair> pair = new ArrayList<>();
		collectKeyFromMemory();
		pair.add(this.keyPair);
		
		return pair;
	}
	
	private void collectKeyFromMemory() {
		try {
			this.keyPair = new KeyPair(loadPublicKey(this.pubKeyPath), loadPrivateKey(this.privKeyPath));
		} catch (Exception e) {
			System.err.println("Problem loading keys..." + e);
		}
	}
	
	public static PrivateKey loadPrivateKey(String filename) throws Exception {
        // Read the key from the file
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        
        // Remove the "BEGIN" and "END" lines and any whitespace from the private key string
        privateKeyPEM = privateKeyPEM
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", ""); // Remove newlines, spaces, etc.
        
        System.out.println("Formatted PrivKey: \n" + privateKeyPEM.substring(0, 100) + "\n");
        
        // Decode the Base64 encoded string into a byte array
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
        
        // Create a key specification for the private key
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        // Create a KeyFactory for the RSA algorithm (or EC for elliptic curve keys)
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        // Generate the PrivateKey object
        return keyFactory.generatePrivate(keySpec);
    }
	
	public static PublicKey loadPublicKey(String filename) throws Exception {
		String publicKeyPEM = new String(Files.readAllBytes(Paths.get(filename)));
		// Remove the "BEGIN" and "END" lines and any whitespace from the public key string
        publicKeyPEM = publicKeyPEM
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", ""); // Remove newlines and other whitespace
        
        System.out.println("Formatted PubKey: \n" + publicKeyPEM.substring(0, 20) + "\n");
        
        // Decode the Base64 encoded string into a byte array
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
                    
        // Create a key specification for the public key
        EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                        
        // Create a key factory for the RSA algorithm (or "EC" for elliptic curve keys)
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");        

        // Generate the PublicKey object
        return keyFactory.generatePublic(keySpec);
       
    }
	
	// Helper method to create configuration file to circumvent the GitHub secure settings, not ideal
	public void createConfigFile(File sshDir) throws IOException {
		this.configFile = new File(sshDir, "config");
			
		String txt = "Host github.com\n"
				+ "  AddKeysToAgent no\n"
				+ "  StrictHostKeyChecking no";
			
		java.nio.file.Files.writeString(this.configFile.toPath(), txt);
	}
		
	// Helper method to delete temporary config
	public void deleteConfigFile() {
		this.configFile.delete();
	}
	
	// Helper method to stop SSH client when necessary
	public void stopService() throws IOException {
		if (this.sshClient.isStarted()) {
			this.sshClient.stop();
			this.sshdSessionFactory.close();
			System.out.println("SSH Service is stopped.");
		} else {
			System.out.println("SSH Service was not started");
		}
	}
}
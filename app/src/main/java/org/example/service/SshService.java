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

/*
 * Service class to help with establishing a connection to GitHub using SSH
 */
public class SshService {
	
	// Global variables for necessary SSH components
	private TransportConfigCallback transportConfigCallback;
	private SshClient sshClient;
	private SshdSessionFactory sshdSessionFactory = null;
	private String privKeyPath;
	private String pubKeyPath;
	private KeyPair keyPair;
	
	// Global variables for configuration file helps getting around security (not great)
	private File configFile;
	
	// Set default SSH directory to .ssh
	private final File defaultSshDir = new File(FS.DETECTED.userHome(), "/.ssh");
	
	// Constructor for loading public/private key pair (really .pem files that contain the keys, also why an IOException is thrown)
	@SuppressWarnings("unused")
	public SshService(String publicKeyPath, String privateKeyPath) throws IOException{
		
	    // Set up SSH client with default client identity
	    this.sshClient = SshClient.setUpDefaultClient();
	    this.sshClient.setClientIdentityLoader(ClientIdentityLoader.DEFAULT);
	    this.sshClient.start();
	    
	    // Set global variables to file paths that were passed from GitService, so they can be used for access and converting to Java objects
	    this.pubKeyPath = publicKeyPath;
	    this.privKeyPath = privateKeyPath;
	    
	    createConfigFile(defaultSshDir);
	    
	    // IMPORTANT STUFF here: 
	    //   --> Used the ".setDefaultKeysProvider(File -> Iterable<KeyPair>)" to pass converted keys to the SshdSession Factory
	    //       (The Factory Builder still requires you to set the Home and SSH directories, which is why those are still there)
	    this.sshdSessionFactory = new SshdSessionFactoryBuilder()
                .setPreferredAuthentications("publickey")
                .setHomeDirectory(FS.DETECTED.userHome())
                .setSshDirectory(defaultSshDir)
                .setDefaultKeysProvider(this::createKeyPairSafely)
                .build(null);

	    // Ensure the session factory is not null before using it
	    if (this.sshdSessionFactory == null) {
	    	throw new IllegalStateException("SSH session factory is null.");
	    }

	    // Create the TransportConfigCallback object that will be used when establishing a connection to GitHub
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
	
	// Ran into a few issues with unhandled Exceptions when trying to get the lambda/arrow function in the SshdSessionFactory to work properly,
	//   so I ended up making this try/catch method to do it.
	// TODO --> make this cleaner...
	private Iterable<KeyPair> createKeyPairSafely(File f) {
		Iterable<KeyPair> safePair = null;
		try {
	        safePair = createKeyPair(f);
	    } catch (Exception e) {}
	    if (safePair == null)
	    	throw new IllegalStateException("Failed to create key pair");
	    return safePair;
	}
	
	// The real helper method that returns the required Iterable<KeyPair> object, calls collectKeysFromMemory() to add them to the Iterable
	private Iterable<KeyPair> createKeyPair(File f) throws Exception{		
		List<KeyPair> pair = new ArrayList<>();
		collectKeyFromMemory();
		pair.add(this.keyPair);
		
		return pair;
	}
	
	// Helper method that just represents the logic of loading BOTH the Public & PrivateKey objects into the KeyPair object
	private void collectKeyFromMemory() {
		try {
			this.keyPair = new KeyPair(loadPublicKey(this.pubKeyPath), loadPrivateKey(this.privKeyPath));
		} catch (Exception e) {
			System.err.println("Problem loading keys..." + e);
		}
	}
	
	// Method to take a PEM-formatted private key and convert it into a PrivateKey object
	public static PrivateKey loadPrivateKey(String filename) throws Exception {
        // Read the private key from the file
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        
        // Remove "BEGIN", "END", and whitespace from the key string
        privateKeyPEM = privateKeyPEM
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
        
        // Debugging print statement to verify that the private key is copying and being formatted correctly
        System.out.println("Formatted PrivKey: \n" + privateKeyPEM.substring(0, 100) + "\n");
        
        // Decode the Base64-encoded String into a byte array to be passed to key spec
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
        
        // Create a key specification for the private key (always PKCS8 from what I could find)
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        // Create a KeyFactory for the RSA algorithm
        // TODO figure out what to do for ED25519 keys, because that is currently a bit of a headache
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        // Generate & return the PrivateKey object
        return keyFactory.generatePrivate(keySpec);
    }
	
	public static PublicKey loadPublicKey(String filename) throws Exception {
        // Read the public key from the file
		String publicKeyPEM = new String(Files.readAllBytes(Paths.get(filename)));
		
		// Remove "BEGIN", "END", and whitespace from the key string
        publicKeyPEM = publicKeyPEM
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
        
        // Debugging print statement to verify that the private key is copying and being formatted correctly
        System.out.println("Formatted PubKey: \n" + publicKeyPEM.substring(0, 20) + "\n");
        
        // Decode the Base64-encoded String into a byte array to be passed to key spec
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
                    
        // Create a key specification for the public key (X509 seems to be the standard)
        EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                        
        // Create a key factory for the RSA algorithm
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");        

        // Generate & return the PublicKey object
        return keyFactory.generatePublic(keySpec);
       
    }
	
	// Helper method to create configuration file to circumvent the GitHub secure settings (not ideal)
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
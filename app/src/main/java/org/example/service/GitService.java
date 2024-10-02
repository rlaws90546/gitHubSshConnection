package org.example.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.lang.Process;
import java.lang.IllegalStateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.TransportException;
import org.apache.commons.io.FileUtils;

import org.example.service.SshService;

/**
 *  Class to provide App.java with methods needed to clone repositories & push changes to GitHub.
 */
public class GitService {
	
	// Variables for repository to be cloned, should be in the format of "git@github.com/userName/repoName.git"
	private String repo;
	// Path to the local directory where Git commands should be called from (also destination for clone command)
	private Path localDir;
	// Instance of jGit's Git to perform necessary commands
	private Git git;
	// Instance of SSH service to standardize creating SSH client and generate a session
	private SshService sshService;
	
	@SuppressWarnings("unused")
	private final Logger log = LoggerFactory.getLogger(getClass());

	
	/* 
	 * OLD CONSTRUCTORS
	 * Constructor used when SSH key is in expected directory --> "Users or C:/.ssh"
	 */
    public GitService(String repoName, String cloneDirName) throws IOException{

    	this.repo = repoName;
	    this.localDir = Paths.get(cloneDirName).toAbsolutePath().normalize();
	    
	    try {
        	if (gitRepoInitialized(this.localDir)) {
        		git = Git.open(this.localDir.toFile());
        	} else {	
        		git = Git.init().setDirectory(this.localDir.toFile()).call();
        	}
		} catch (IllegalStateException | GitAPIException e) {
			e.printStackTrace();
		}
    }
    
    /* 
     * Helper method to determine if a Git repository has been initialized in the user-specified directory
     */
    private boolean gitRepoInitialized(Path localDir) {
    	try {
    		Process gitCheck = Runtime.getRuntime().exec("git rev-parse --is-inside-work-tree", null, localDir.toFile());
    		BufferedReader stdInput = new BufferedReader(new InputStreamReader(gitCheck.getInputStream()));
    		if (stdInput.readLine().trim() == "true")
    			return true;
    	} catch (IOException err) {
    		err.printStackTrace();
    	}
    	return false;
    }
    
    // Helper methods to create SSH service
    public void createSshService() {
    	this.sshService = new SshService();
    }
    public void createSshService(String pubKeyPath, String privKeyPath) {
    	try {
			this.sshService = new SshService(pubKeyPath, privKeyPath);
		} catch (IOException e) {
			System.err.println("Error creating SSH service with private key path & private key loaded:\n");
			e.printStackTrace();
		}
    } 
    
    /* 
	 * Helper method to clone repository from GitHub.
	 */
	@SuppressWarnings("static-access")
	public void cloneRepository() throws IOException {
    	System.out.println("Cloning " + this.repo + " to " + this.localDir.toString());
    	try {
    		File dir = new File(this.localDir.toString());
    		FileUtils.cleanDirectory(dir);
    		if (sshService != null) {
    			git.cloneRepository().setTransportConfigCallback(sshService.getTransportConfigCallback())
    			.setDirectory(this.localDir.toFile())
    			.call();
    		}
    	} catch (GitAPIException err) {
    		throw new IllegalStateException("\nCould not clone Git repository: ", err);
	    }
    }
	
	/* 
	 * Helper method to add, commit, & push changes made to the Git repository.
	 */
    public final void addCommitPush() throws IOException {
    	try {
            // Add, commit, and push changes
            git.add().addFilepattern(".").call();
            
            LocalDateTime dateTime = LocalDateTime.now();
            DateTimeFormatter formatObj = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");  
            String formattedDate = dateTime.format(formatObj);
            
            //System.out.println("Commit Message --> Automated commit: added changes to repository at -> " + formattedDate);
           
            git.commit().setMessage("Automated commit: added changes to repository at -> " + formattedDate).call();
            if (sshService != null) {
	            git.push()
	               .setRemote(repo)
	               .setTransportConfigCallback(sshService.getTransportConfigCallback())
	               .call();
	            System.out.println("\nPushed changes to remote repository successfully!");
            } else {
            	System.out.println("\nSomething happened - SSH service is null");
            }
            
        } catch (GitAPIException err) {
            err.printStackTrace();
        }
        
    }
    
    /* 
	 * Helper method to stop the SSH client
	 */
    public final void stopSshService() {
    	try {
			this.sshService.stopService();
		} catch (IOException err) {
			err.printStackTrace();
		}
    }
    
    // Used to allow App.java to call deleteConfigFile in SshService
    public final void deleteConfigFile() { this.sshService.deleteConfigFile(); }
}

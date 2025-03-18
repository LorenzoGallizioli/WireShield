package com.wireshield.windows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import com.wireshield.av.FileManager;

public class WFPManager {

    public static boolean createCIDRFile(String defaultPeerPath, String peerName){
        
        Path filePath = Paths.get(defaultPeerPath + peerName + "_permits.csv");
        try {

            if (Files.exists(filePath)) {
                filePath.toFile().delete();
            }

            String newData = "";

            // Crea il file se non esiste
            Files.createFile(filePath);

            // Scrivi i dati nel file
            Files.write(filePath, newData.getBytes(), StandardOpenOption.APPEND);

            return true;
        } catch (IOException e) {
            System.err.println("Error occurred during file creaton: " + e.getMessage());
            return false;
        }
    }

    public static boolean deleteCIDRFile(String defaultPeerPath, String peerName){
        
        Path filePath = Paths.get(defaultPeerPath + peerName + "_permits.csv");
        try {
            Files.delete(filePath);
            return true;
        } catch (IOException e) {
            System.err.println("Error occurred during file deletion: " + e.getMessage());
            return false;
        }
    }
    
    public static boolean addCIDR_permit(String defaultPeerPath, String peerName, String cidr){
        
        Path path = Paths.get(defaultPeerPath + peerName + "_permits.csv"); 
        try {

            if (!Files.exists(path)) {
                createCIDRFile(defaultPeerPath, peerName);
            }

            String newCidr = "," + cidr;

            Files.write(path, (newCidr).getBytes(), StandardOpenOption.APPEND);

            return true;

        } catch (IOException e) {
            System.err.println("Error occurred during file manipulation: " + e.getMessage());
            return false;
        }
    }

    public static boolean removeCIDR_permit(String defaultPeerPath, String peerName, String cidr) {
        Path path = Paths.get(defaultPeerPath + peerName + "_permits.csv");
        try {
            String content = new String(Files.readAllBytes(path));
            
            String newContent = content.replace("," + cidr, "");
            
            Files.write(path, newContent.getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
            
            return true;
        } catch (IOException e) {
            System.err.println("Error occurred during file manipulation: " + e.getMessage());
            return false;
        }
    }

    public static List<String> getAllCIDR_permit(String defaultPeerPath, String peerName){
        
        Path path = Paths.get(defaultPeerPath + peerName + "_permits.csv");
        List<String> cidrList = new ArrayList<>();
        try {
            List<String> lines = Files.readAllLines(path);

            for (String line : lines) {
                String[] cidrs = line.split(",");
                for (String cidr : cidrs) {
                    cidrList.add(cidr.trim());  // Rimuovi eventuali spazi prima o dopo il CIDR
                    if (cidr.equals("")) cidrList.remove(cidr);  // Rimuovi eventuali stringhe vuote
                }
            }
            return cidrList;
        } catch (IOException e) {
            System.err.println("Error occurred during file reading: " + e.getMessage());
            return null;
        }
    }

    public static String makeCommand(List<String> cidr){

        String cmd = FileManager.getProjectFolder() + "\\bin\\main.exe -permit ";
        for (String c : cidr) {
            cmd += c + " ";
        }
        return cmd;
    }
}

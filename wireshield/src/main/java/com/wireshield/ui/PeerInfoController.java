package com.wireshield.ui;

import com.wireshield.wireguard.Peer;
import com.wireshield.wireguard.PeerManager;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class PeerInfoController {

    @FXML private Label nameValue;
    //@FXML private Label idValue;
    @FXML private Label publicKeyValue;
    @FXML private Label privateKeyValue;
    @FXML private Label addressValue;
    @FXML private Label endPointValue;
    @FXML private Label dnsValue;
    @FXML private Label mtuValue;
    @FXML private Label presharedKeyValue;
    @FXML private Label allowedIPsValue;
    
    @FXML private Button showPrivateKeyBtn;
    @FXML private Button editPeerBtn;
    @FXML private Button deletePeerBtn;
    
    private Peer currentPeer;
    
    private PeerDeletionListener deletionListener;
    
    public void setDeleionListener(PeerDeletionListener listener) {
        this.deletionListener = listener;
    }

    
    @FXML
    public void initialize() {

        // Configura il pulsante modifica
        //editPeerBtn.setOnAction(event -> handleEditPeer());
        
        // Configura il pulsante delete
        deletePeerBtn.setOnAction(event -> handleDeletePeer());
        
    }
    
    /**
     * Imposta il peer corrente e aggiorna l'UI con i suoi dati
     */
    public void setPeer(Peer peer) {
        this.currentPeer = peer;
        updateUI();
    }
    
    /**
     * Aggiorna l'interfaccia utente con i dati del peer
     */
    private void updateUI() {
        if (currentPeer == null) return;
        
        nameValue.setText(currentPeer.getName());
        publicKeyValue.setText(currentPeer.getPublicKey());
        addressValue.setText(currentPeer.getAddress());
        endPointValue.setText(currentPeer.getEndPoint());
        dnsValue.setText(currentPeer.getDNS());
        mtuValue.setText(currentPeer.getMTU());
        presharedKeyValue.setText(currentPeer.getPublicKey());
        allowedIPsValue.setText(currentPeer.getAllowedIps());
    }
    
    /**
     * Gestisce l'azione di modifica del peer
     */
    private void handleEditPeer() {
        // Implementa la logica per modificare il peer
        // Questo potrebbe aprire una nuova finestra di dialogo o un altro pannello
        System.out.println("Modifica peer: " + currentPeer.getName());
    }
    
    /**
     * Gestisce l'azione di eliminazione del peer
     */
    private void handleDeletePeer() {
        Alert confirmDialog = new Alert(AlertType.CONFIRMATION);
        confirmDialog.setTitle("Conferma Eliminazione");
        confirmDialog.setHeaderText("Eliminare il peer " + currentPeer.getName() + "?");
        confirmDialog.setContentText("Questa operazione non può essere annullata.");
        
        confirmDialog.showAndWait().ifPresent(response -> {
            if (response == javafx.scene.control.ButtonType.OK) {
            	
            	if (deletionListener != null) {
            		deletionListener.onPeerDeleted(currentPeer);
                }
            	
                // Implementa la logica per eliminare il peer
                System.out.println("Peer eliminato: " + currentPeer.getName());
            }
        });
    }
}
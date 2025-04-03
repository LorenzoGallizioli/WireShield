package com.wireshield.ui;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wireshield.av.FileManager;
import com.wireshield.windows.WFPManager;
import com.wireshield.wireguard.Peer;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;

public class PeerInfoController {

    private static final Logger logger = LogManager.getLogger(PeerInfoController.class);

    @FXML
    private Label nameValue;
    @FXML
    private Label publicKeyValue;
    @FXML
    private Label addressValue;
    @FXML
    private Label endPointValue;
    @FXML
    private Label dnsValue;
    @FXML
    private Label mtuValue;
    @FXML
    private Label presharedKeyValue;
    @FXML
    private Label allowedIPsValue;
    @FXML
    private Button editPeerBtn;
    @FXML
    private Button deletePeerBtn;
    
    private Peer currentPeer;
    
    private PeerOperationListener operationListener;

    // CIDR variables
    @FXML
    private TextField cidrTextField;
    @FXML
    private FlowPane cidrCardsContainer;
    
    private ObservableList<String> cidrList = FXCollections.observableArrayList();
    private Peer peer;
    private String defaultPeerPath = FileManager.getProjectFolder() + FileManager.getConfigValue("PEER_STD_PATH");
    

    // Pattern regex per validare il formato CIDR (IP/subnet)
    private static final String CIDR_PATTERN = 
            "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))$";
    private Pattern pattern = Pattern.compile(CIDR_PATTERN);

    
    public void setOperationListener(PeerOperationListener listener) {
        this.operationListener = listener;
    }

    @FXML
    public void initialize() {
        deletePeerBtn.setOnAction(event -> handleDeletePeer());
        editPeerBtn.setOnAction(event -> handleEditPeer());

        logger.debug("Inizializzazione del controller CIDR");
        
        // Configurazione dell'evento keypress per il TextField
        cidrTextField.addEventHandler(KeyEvent.KEY_PRESSED, event -> {
            if (event.getCode() == KeyCode.ENTER) {
                processCIDRInput();
                event.consume();
            }
        });
    }
    
    /**
     * Sets the current peer and updates the UI with its data.
     */
    public void setPeer(Peer peer) {
        this.currentPeer = peer;
        updateUI();
    }
    
    /**
     * Updates the user interface with the peer's data.
     */
    private void updateUI() {
        if (currentPeer == null) return;
        
        nameValue.setText(currentPeer.getName());
        publicKeyValue.setText(currentPeer.getPublicKey());
        addressValue.setText(currentPeer.getAddress());
        endPointValue.setText(currentPeer.getEndPoint());
        dnsValue.setText(currentPeer.getDNS());
        mtuValue.setText(currentPeer.getMTU());
        presharedKeyValue.setText(currentPeer.getPresharedKey());
        allowedIPsValue.setText(currentPeer.getAllowedIps());
        
        deletePeerBtn.setDisable(false);
        editPeerBtn.setDisable(false);

    }
    
    /**
     * Handles the peer edit action.
     */
    private void handleEditPeer() {
    	
    	if(operationListener != null) {
    		operationListener.onPeerModified(currentPeer);
    	}
    	
    }
    
    /**
     * Handles the peer deletion action.
     */
    private void handleDeletePeer() {
        Alert confirmDialog = new Alert(AlertType.CONFIRMATION);
        confirmDialog.setTitle("Delete Confirmation");
        confirmDialog.setHeaderText("Delete peer " + currentPeer.getName() + "?");
        confirmDialog.setContentText("This action cannot be undone.");
        
        confirmDialog.showAndWait().ifPresent(response -> {
            if (response == javafx.scene.control.ButtonType.OK) {
            
                if (operationListener != null) {
                	operationListener.onPeerDeleted(currentPeer);
                }
                
                deletePeerBtn.setDisable(true);
                editPeerBtn.setDisable(true);
                
                System.out.println("Peer deleted: " + currentPeer.getName());
            }
        });
    }
    
    private void processCIDRInput() {
        String cidrInput = cidrTextField.getText().trim();
        
        logger.debug("Processing CIDR input: {}", cidrInput);
        
        // Verifica se l'input è valido
        if (!cidrInput.isEmpty() && isValidCIDR(cidrInput)) {
            // Aggiungi il CIDR alla lista se non è già presente
            if (!cidrList.contains(cidrInput)) {
                cidrList.add(cidrInput);
                
                // Crea una card per visualizzare il CIDR
                createCIDRCard(cidrInput);

                String peerNameWithoutExtension = currentPeer.getName().contains(".") ? currentPeer.getName().substring(0, currentPeer.getName().lastIndexOf(".")) : currentPeer.getName();
                WFPManager.addCIDR_permit(defaultPeerPath, peerNameWithoutExtension, cidrInput);
                
                logger.info("CIDR aggiunto: {}", cidrInput);
            } else {
                logger.debug("CIDR già presente nella lista: {}", cidrInput);
            }
            
            // Pulisci il campo di input
            cidrTextField.clear();
        } else {
            logger.warn("CIDR non valido: {}", cidrInput);
        }
    }
    
    private boolean isValidCIDR(String cidr) {
        Matcher matcher = pattern.matcher(cidr);
        return matcher.matches();
    }
    
    private void createCIDRCard(String cidr) {
        HBox card = new HBox();
        card.getStyleClass().add("cidr-card");
        card.setPadding(new Insets(5, 10, 5, 10));
        card.setStyle("-fx-background-color: #333333; -fx-background-radius: 5; -fx-border-radius: 5; -fx-margin: 3;");
        
        Label cidrLabel = new Label(cidr);
        cidrLabel.setStyle("-fx-text-fill: #FFFFFF;");
        card.getChildren().add(cidrLabel);
        
        // Aggiunge la possibilità di rimuovere il CIDR cliccando sulla card
        card.setOnMouseClicked(event -> {
            cidrCardsContainer.getChildren().remove(card);
            cidrList.remove(cidr);

            String peerNameWithoutExtension = currentPeer.getName().contains(".") ? currentPeer.getName().substring(0, currentPeer.getName().lastIndexOf(".")) : currentPeer.getName();
            WFPManager.removeCIDR_permit(defaultPeerPath, peerNameWithoutExtension, cidr);
            
            logger.debug("CIDR rimosso: {}", cidr);
        });
        
        cidrCardsContainer.getChildren().add(card);
    }
    
    public TextField getCidrTextField() {
        return cidrTextField;
    }

    public void loadCIDRs(){
        String peerNameWithoutExtension = currentPeer.getName().contains(".") ? currentPeer.getName().substring(0, currentPeer.getName().lastIndexOf(".")) : currentPeer.getName();
        List<String> CIDRList = WFPManager.getAllCIDR_permit(defaultPeerPath, peerNameWithoutExtension);

        for (String cidr : CIDRList) {
            createCIDRCard(cidr);
        }
    }
}
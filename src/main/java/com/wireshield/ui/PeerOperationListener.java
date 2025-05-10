package com.wireshield.ui;

import com.wireshield.wireguard.Peer;

/**
 * Listener interface for peer operations.
 * This interface defines methods to handle events related to peer and defined in PeerInfoController class, 
 * need to be in a separate file beacause must be used in either PeerInfoController or UserInterface -> Used like a bridge between
 * this 2 classes.
 */
public interface PeerOperationListener {
	void onPeerDeleted(Peer peer);
	void onPeerModified(Peer peer);
}

package com.wireshield.ui;

import com.wireshield.wireguard.Peer;

public interface PeerOperationListener {
	void onPeerDeleted(Peer peer);
	void onPeerModified(Peer peer);
}

package com.wireshield.ui;

import com.wireshield.wireguard.Peer;

public interface PeerDeletionListener {
	void onPeerDeleted(Peer peer);
}

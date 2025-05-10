package com.wireshield.enums;

/**
 * The connectionStates enum represents the possible states of a connection. It
 * is used to manage and track the connection status in a system.
 */
public enum connectionStates {
	CONNECTED, // The connection is currently established and active.

	CONNECTION_IN_PROGRESS, // The connection is in the process of being established. This state indicates
							// that the system is attempting to connect but has not yet succeeded.

	DISCONNECTED, // The connection is currently not established. This state indicates that the
					// system is disconnected or the connection has been terminated.
}

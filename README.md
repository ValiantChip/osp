# OSP

OSP is an implementaion of the open screen network and application protocol 

## Use

The open screen network protocol is a set of network protocols to allow two devices to discover eachother and establish a secure connection. The implementation provided by osp uses the protocols described by <https://www.w3.org/TR/openscreen-network/>: 
- DNS-SD to allow for agents to discover eachother on the local area network
- TLS 1.3 to establish a secure unauthenticated connection
- Spake2 to authenticate connected agents
- Quic as a transport layer

The open screen application protocol is a seperate protocol that allows for remote playback, presentation, or streaming to be shared between devices, and allows for a devices to control the media that is being played remotely. While the open screen application protocol is not dependent on a specific connection method, this implementation uses the Open Screen Network Protocol. Specifically, this implementation implements the Remote Playback protocol as both a client that can serve a local video and control remote playback and a server that can recieve and play remote media. The local video is served by the client over http. Playback is handled by the server using vlc.

### Note

Because the provided client serves video over http, any videos cast using this implementation are not secure.

### Requirements

- Go 1.24.6
- libvlc v3.x
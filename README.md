<a href="https://tm9657.de?ref=github"><p align="center"><img width=250 src="https://cdn.tm9657.de/tm9657/images/generic_socket_rooms.png" /></p></a>
<p align="center">
    <a href="https://tm9657.de"><img src="https://img.shields.io/badge/website-more_from_us-C0222C.svg?style=flat&logo=PWA"> </a>
	  <a href="https://discord.ca9.io"><img src="https://img.shields.io/discord/673169081704120334?label=discord&style=flat&color=5a66f6&logo=Discord"></a>
	  <a href="https://twitter.com/tm9657"><img src="https://img.shields.io/badge/twitter-follow_us-1d9bf0.svg?style=flat&logo=Twitter"></a>
	  <a href="https://www.linkedin.com/company/tm9657/"><img src="https://img.shields.io/badge/linkedin-connect-0a66c2.svg?style=flat&logo=Linkedin"></a>
    <a href="https://merch.ca9.io"><img src="https://img.shields.io/badge/merch-support_us-red.svg?style=flat&logo=Spreadshirt"></a>
</p>


# Y-Phoenix Provider
> Phoenix Channels Provider for Yjs

The Phoenix Channels Provider is meant to be used as a Yjs Provider for [Generic Socket Rooms](https://github.com/TM9657/generic-socket-rooms). It enables End-to-End encryption, realtime communication between multiple users.

## Quick Start

### Install dependencies

```sh
npm i @tm9657/y-phoenix
```

### Start a y-phoenix server

Please use: [Generic Socket Rooms](https://github.com/TM9657/generic-socket-rooms)

### Client Code:

```js
import * as Y from 'yjs'
import { PhoenixProvider } from '@tm9657/y-phoenix'

const doc = new Y.Doc()
const wsProvider = new PhoenixProvider(
  socket, // Socket from Generic Socket Rooms
  props.room, // Room, please make sure this one is not guessable. Otherwise DDOS attacks on this room are possible, if you do not further prevent them, e.g by checking permission on the server before sending JWT
  props.token, // JWT Token, signed for the room, please have a look at Generic Socket Rooms for more information
  props.password, // Password for End to End encryption. E.g generated on the client and shared by QR Code or as part of the URL
  ydoc // Yjs Document
)
```


---
**Provided by TM9657 GmbH with ❤️**
### Check out some of our products:
- [Kwirk.io](https://kwirk.io?ref=github) (Text Editor with AI integration, privacy focus and offline support)

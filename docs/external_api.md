## ITunes API
Can be used to find artists, their albums and tracks. Also can be a good base for artist following system.
### Examples:
#### Chain of requests to get a list of songs from an album:
1. `https://itunes.apple.com/lookup?id=ARTIST_ID&entity=album&limit=200&country=ru`
2. `https://itunes.apple.com/lookup?id=ALBUM_ID&entity=song&country=ru`
#### Search for an artist:
`https://itunes.apple.com/search?term=Kangi&entity=musicArtist&limit=200&country=ru`
#### Search for an album
`https://itunes.apple.com/search?term=Kangi&entity=album&limit=200&country=ru`
#### Search for songs
`https://itunes.apple.com/search?term=Kangi&entity=song&limit=200&country=ru`

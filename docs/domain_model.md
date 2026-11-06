User - user. Independent entity. Server can have many Users.
Artist - music artist. Server can have many Artists but they are created the first time a User looks for him or his songs.
Album - a collection of tracks.
Playlist - playlist. Created by User, stores relation to a music track. Single User can have multiple playlists. Can be private, shared or public.
Favorites - a kind of playlist that stores "liked" tracks. Created with User registration. Cannot be named, tracks are stored in an order of addition.
Track - entity describing music stored in database. Depends on TrackAsset. Playlists can share single Track.
TrackAsset - physical file stored on server.
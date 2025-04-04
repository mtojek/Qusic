package lyrics

import (
	"github.com/qusicapp/qusic/youtube"
	"time"
)

func GetSongYTMusicPlain(videoId string) (Song, error) {
	lyrics, err := (*youtube.MusicClient).LyricsPlain(nil, videoId)
	return Song{
		LyricSource: "YouTube Music (" + lyrics.Source + ")",
		PlainLyrics: lyrics.Lyrics,
	}, err
}

func GetSongYTMusicSynced(videoId string) (Song, error) {
	lyrics, src, err := (*youtube.MusicClient).LyricsSynced(nil, videoId)
	var syncedLyrics []SyncedLyric
	for _, lyric := range lyrics {
		syncedLyrics = append(syncedLyrics, SyncedLyric{
			At:    time.Duration(lyric.CueRange.StartTimeMilliseconds.Int()) * time.Millisecond,
			Index: len(syncedLyrics),
			Lyric: lyric.LyricLine,
		})
	}
	return Song{
		LyricSource:  "YouTube Music (" + src + ")",
		SyncedLyrics: syncedLyrics,
	}, err
}

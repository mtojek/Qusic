package streamer

import (
	"bytes"
	"fmt"
	"github.com/qusicapp/qusic/preferences"
	"github.com/qusicapp/qusic/spotify"
	"github.com/qusicapp/qusic/streamer/aac"

	"github.com/Eyevinn/mp4ff/bits"
	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/gopxl/beep"
)

func NewSpotifyMP4AACStreamer(trackId string, client *spotify.Client) (beep.StreamSeekCloser, beep.Format, error) {
	buf, err := client.GetMP4(trackId)
	if err != nil {
		return nil, beep.Format{}, err
	}
	file, err := mp4.DecodeFile(buf)
	if err != nil {
		return nil, beep.Format{}, err
	}

	mp4a := file.Moov.Trak.Mdia.Minf.Stbl.Stsd.Mp4a
	format := beep.Format{
		SampleRate:  beep.SampleRate(mp4a.SampleRate),
		NumChannels: int(mp4a.ChannelCount),
	}
	audioConfig := mp4a.Esds.DecConfigDescriptor.DecSpecificInfo.DecConfig
	if len(audioConfig) != 2 {
		return nil, beep.Format{}, ErrAudioConfigMissing
	}
	r := bits.NewReader(bytes.NewReader(audioConfig))
	trex := file.Moov.Mvex.Trex

	var samples []mp4.FullSample

	for i, box := range file.Children {
		if box.Type() == "moof" {
			moof := box.(*mp4.MoofBox)
			trun := moof.Traf.Trun

			mdat := file.Children[i+1].(*mp4.MdatBox)

			trun.AddSampleDefaultValues(moof.Traf.Tfhd, trex)

			samples = append(samples, trun.GetFullSamples(0, 0, mdat)...)
		}
	}

	if !preferences.Preferences.Bool("debug_mode") {
		return nil, beep.Format{}, fmt.Errorf("The aac decoder is not yet functional. Enable debug mode or wait for the aac decoder to be finished")
	}

	return &fmp4Streamer{
		frames:               samples,
		objectType:           r.MustRead(5),
		frequencyIndex:       r.MustRead(4),
		channelConfiguration: r.MustRead(4),
		frameLengthFlag:      r.MustRead(1),
		dependsOnCoreCoder:   r.MustRead(1),
		extensionFlag:        r.MustRead(1),
		decConfig:            mp4a.Esds.DecConfigDescriptor.DecSpecificInfo.DecConfig,
	}, format, nil
}

type fmp4Streamer struct {
	objectType, frequencyIndex, channelConfiguration, frameLengthFlag, dependsOnCoreCoder, extensionFlag uint

	decConfig []byte

	frames []mp4.FullSample

	i int

	err    error
	closed bool
}

func (s *fmp4Streamer) Stream(samples [][2]float64) (n int, ok bool) {
	if s.closed {
		s.err = ErrClosed
		return 0, false
	}
	frame := s.frames[s.i]
	fmt.Println("frame", s.i)

	samples0, _ := aac.DecodeAACFrame(frame.Data, s.frequencyIndex, s.frameLengthFlag)

	for i := range samples {
		samples[i][0] = samples0[i]
		//samples[i][1] = samples1[i]
	}

	s.i++
	return len(samples), true
}
func (s fmp4Streamer) Err() error { return s.err }
func (s fmp4Streamer) Close() error {
	if s.closed {
		return ErrAlreadyClosed
	}
	s.closed = true
	return nil
}
func (s fmp4Streamer) Len() int {
	return 512 * len(s.frames)
}
func (s fmp4Streamer) Position() int {
	return s.i * 512
}
func (s fmp4Streamer) Seek(i int) error {
	s.i = i / 512
	return nil
}

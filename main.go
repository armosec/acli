package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/enescakir/emoji"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

func main() {

	title0 := color.New(color.Bold, color.FgHiWhite).FprintfFunc()

	title0(os.Stdout, "ARMO security scanner loading\n")

	workloads, err := HandleInput()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	s := spinner.New(spinner.CharSets[4], 100*time.Millisecond) // Build our new spinner

	if isatty.IsTerminal(os.Stdout.Fd()) {
		s.Start()
	}

	responseMap, err := RegoHandler(workloads)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//fmt.Printf("response: %v\n", responseMap)
	happyEmojies := [...]interface{}{emoji.SmilingFace, emoji.Sunglasses, emoji.ThumbsUp, emoji.OkHand}
	sadEmojies := [...]interface{}{emoji.SadButRelievedFace, emoji.FaceWithOpenMouth, emoji.FaceWithRaisedEyebrow, emoji.FaceWithRollingEyes}

	rand.Seed(time.Now().Unix())

	success := color.New(color.Bold, color.FgGreen).FprintfFunc()
	failure := color.New(color.Bold, color.FgHiRed).FprintfFunc()
	failure_text := color.New(color.Faint, color.FgHiRed).FprintfFunc()
	title1 := color.New(color.FgHiWhite).FprintfFunc()

	if isatty.IsTerminal(os.Stdout.Fd()) {
		s.Stop()
	}

	for fileObject, fileResponse := range responseMap {
		title1(os.Stdout, "%s: \n", fileObject)
		if len(fileResponse) == 0 {
			success(os.Stdout, "passed %v\n", happyEmojies[rand.Intn(len(happyEmojies))])
		} else {
			for i := range fileResponse {
				failure(os.Stdout, "failed %v", sadEmojies[rand.Intn(len(sadEmojies))])
				failure_text(os.Stdout, " - %s\n", fileResponse[i].AlertMessage)
			}
		}
	}
}

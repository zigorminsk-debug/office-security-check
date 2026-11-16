package main

import (
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("Office Security Check")

	label := widget.NewLabel("Office Security Check Tool")
	button := widget.NewButton("Scan Network", func() {
		label.SetText("Scanning...")
	})

	w.SetContent(container.NewVBox(
		label,
		button,
	))

	w.ShowAndRun()
}

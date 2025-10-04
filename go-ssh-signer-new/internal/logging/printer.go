package logging

import (
	"fmt"
	"io"
)

type Verbosity int

const (
	Quiet       Verbosity = iota // 0 (no extra chatter)
	Normal                       // 1 (default)
	Verbose                      // 2 (-vv)
	VeryVerbose                  // 3 (-vvv or more)
)

type Printer struct {
	writer io.Writer
	level  Verbosity
}

func NewPrinter(w io.Writer, level int) *Printer {
	v := VeryVerbose
	if level < int(Quiet) {
		v = Quiet
	}
	if level <= int(VeryVerbose) {
		v = Verbosity(level)
	}
	return &Printer{writer: w, level: v}
}

func (p *Printer) Printf(format string, args ...any) {
	fmt.Fprintf(p.writer, format, args...)
}

func (p *Printer) Println(format string) {
	fmt.Fprintln(p.writer, format)
}

func (p *Printer) V(l Verbosity) *conditional {
	return &conditional{printer: p, need: l}
}

type conditional struct {
	printer *Printer
	need    Verbosity
}

func (c *conditional) Printf(format string, args ...any) {
	if c.printer.level >= c.need {
		fmt.Fprintf(c.printer.writer, format, args...)
	}
}

func (c *conditional) Println(format string) {
	if c.printer.level >= c.need {
		fmt.Fprintln(c.printer.writer, format)
	}
}

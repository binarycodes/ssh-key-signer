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
	Writer io.Writer
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
	return &Printer{Writer: w, level: v}
}

func (p *Printer) Printf(format string, args ...any) {
	fmt.Fprintf(p.Writer, format, args...)
}

func (p *Printer) Println(format string) {
	fmt.Fprintln(p.Writer, format)
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
		fmt.Fprintf(c.printer.Writer, format, args...)
	}
}

func (c *conditional) Println(format string) {
	if c.printer.level >= c.need {
		fmt.Fprintln(c.printer.Writer, format)
	}
}

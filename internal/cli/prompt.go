package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// prompter implements appleid.Prompter on a TTY (or plain stdin pipes).
type prompter struct {
	in  *os.File
	out io.Writer
}

func newPrompter(out io.Writer) *prompter {
	return &prompter{in: os.Stdin, out: out}
}

func (p *prompter) Notify(msg string) {
	fmt.Fprintln(p.out, msg)
}

func (p *prompter) PromptPassword(label string) (string, error) {
	fmt.Fprint(p.out, label)
	defer fmt.Fprintln(p.out)
	if term.IsTerminal(int(p.in.Fd())) {
		raw, err := term.ReadPassword(int(p.in.Fd()))
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *prompter) PromptCode(label string) (string, error) {
	fmt.Fprint(p.out, label)
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return "", errors.New("no verification code entered")
	}
	return code, nil
}

func (p *prompter) PromptChoice(label string, options []string) (int, error) {
	fmt.Fprintln(p.out, label)
	for i, opt := range options {
		fmt.Fprintf(p.out, "  %d: %s\n", i, opt)
	}
	for {
		fmt.Fprintf(p.out, "Choice (0-%d): ", len(options)-1)
		line, err := p.readLine()
		if err != nil {
			return 0, err
		}
		choice, convErr := strconv.Atoi(strings.TrimSpace(line))
		if convErr == nil && choice >= 0 && choice < len(options) {
			return choice, nil
		}
		fmt.Fprintln(p.out, "  invalid choice")
	}
}

func (p *prompter) readLine() (string, error) {
	line, err := bufio.NewReader(p.in).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

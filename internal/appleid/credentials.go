package appleid

// Credentials is one Apple ID sign-in attempt.
type Credentials struct {
	AppleID  string
	Password string
}

// Prompter is the interactive surface used during sign-in. Implementations read
// from a terminal; tests can script it.
type Prompter interface {
	// PromptPassword asks for a secret without echoing it.
	PromptPassword(label string) (string, error)
	// PromptCode asks for a verification code.
	PromptCode(label string) (string, error)
	// PromptChoice asks the user to pick one of options and returns its index.
	PromptChoice(label string, options []string) (int, error)
	// Notify reports informational progress.
	Notify(msg string)
}

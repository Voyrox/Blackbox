package color

func Ok(text string) string   { return "\033[32m\u2713 " + text + "\033[0m" }
func Fail(text string) string { return "\033[31m\u2717 " + text + "\033[0m" }
func Green(text string) string  { return "\033[32m" + text + "\033[0m" }
func Red(text string) string    { return "\033[31m" + text + "\033[0m" }
func Yellow(text string) string { return "\033[33m" + text + "\033[0m" }
func Cyan(text string) string   { return "\033[36m" + text + "\033[0m" }
func Bold(text string) string   { return "\033[1m" + text + "\033[0m" }

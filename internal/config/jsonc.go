package config

// StripJSONC removes // and /* */ comments and trailing commas so that
// VS Code-style settings files (JSON with comments) parse with encoding/json.
func StripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(in) {
				i++
				out = append(out, in[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++ // now on the closing '/'; the loop increment skips it
		default:
			out = append(out, c)
		}
	}
	return stripTrailingCommas(out)
}

func stripTrailingCommas(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(in) {
				i++
				out = append(out, in[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

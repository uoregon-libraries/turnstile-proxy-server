package main

import (
	"regexp"
	"strings"
)

// A working challenge page needs three things that have nothing to do with how
// the page looks: Cloudflare's Turnstile script in the document head, a form
// that POSTs the solved token back to the original URL, and the glue JS that
// submits that form (and pings the beacon). Rather than make every custom
// template author copy that markup exactly and keep it in sync with TPS, a
// template just marks the spot with an empty <challenge-form> element and TPS
// fills in the rest when it loads the template.
const (
	// turnstileAPISrc is Cloudflare's widget script. Its presence in a template
	// is also how we tell that the author is loading it themselves.
	turnstileAPISrc = "https://challenges.cloudflare.com/turnstile/v0/api.js"

	turnstileScriptTag = `<script src="` + turnstileAPISrc + `" async defer></script>`
)

// challengeFormMarkup is what a <challenge-form> element gets filled with.
// This is *template* source, not final HTML: it is spliced into the template
// before the template is parsed, so html/template escapes the values in
// context, exactly as if the author had written the form by hand.
//
// original_method is what the interrupted request was. TPS normally reads the
// method off the cached request, and only needs this if that cache entry
// expired before the client solved the challenge — see recoverExpiredChallenge.
const challengeFormMarkup = `
<form id="tps-challenge-form" action="{{.PostAction}}" method="POST">
  <input type="hidden" name="request_id" value="{{.RequestID}}" />
  <input type="hidden" name="original_method" value="{{.OriginalMethod}}" />
  <div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="tpsChallengeSolved"></div>
</form>
<script>
  // Send the "is the client JS-enabled?" beacon
  try { navigator.sendBeacon('/.tps/beacon'); } catch (e) {}

  // Submit the challenge form by id, not document.querySelector('form'): a
  // custom template may embed other forms (e.g. a site search bar) ahead of
  // this one, and querySelector('form') would submit the wrong one.
  function tpsChallengeSolved(token) {
    document.getElementById('tps-challenge-form').submit();
  }
</script>
`

var (
	// challengeFormRE matches a <challenge-form> placeholder as a whole
	// element. The first branch is the self-closing form, which has no closing
	// tag to look for; the second is the ordinary one, whose closing tag and
	// everything before it are captured so fallback content (a <noscript>
	// block, say) can be put back inside the element we write out. The inner
	// capture is non-greedy so the nearest closing tag wins.
	//
	// Submatches: 1 = self-closing attributes, 2 = attributes, 3 = fallback
	// content. Only one of 1 and 2 is ever set, so callers can concatenate
	// them to get the attributes regardless of which branch matched.
	challengeFormRE = regexp.MustCompile(`(?is)<challenge-form\b([^>]*?)/\s*>` +
		`|<challenge-form\b([^>]*)>(?:(.*?)</challenge-form\s*>)?`)

	// scriptTagRE matches a <script ...> opening tag. Finding the Turnstile
	// URL inside one of these is how we tell a template that really loads
	// api.js from one that only mentions the URL somewhere it does nothing —
	// a CSP <meta> tag, say, or a comment.
	scriptTagRE = regexp.MustCompile(`(?is)<script\b[^>]*>`)

	headCloseRE = regexp.MustCompile(`(?i)</head\s*>`)
	bodyOpenRE  = regexp.MustCompile(`(?i)<body\b[^>]*>`)
)

// expandChallengeMarkup rewrites a template's source so that every
// <challenge-form> placeholder becomes a working Turnstile form, and the
// Turnstile script is loaded. It returns the rewritten source and how many
// placeholders it found; a source with no placeholder is returned untouched,
// which is what keeps hand-written challenge pages (and the failure page)
// working as they always have.
func expandChallengeMarkup(src string) (string, int) {
	var found = len(challengeFormRE.FindAllStringIndex(src, -1))
	if found == 0 {
		return src, 0
	}

	var out = challengeFormRE.ReplaceAllStringFunc(src, func(match string) string {
		var m = challengeFormRE.FindStringSubmatch(match)

		// Only one of the two attribute captures is ever set, so joining them
		// works whichever branch matched. Attributes are preserved so the
		// element stays styleable (`challenge-form { ... }` or a class); we
		// always write an explicit closing tag, so a self-closing placeholder
		// loses nothing but its slash.
		var attrs = strings.TrimSpace(m[1] + m[2])
		if attrs != "" {
			attrs = " " + attrs
		}

		// The author's fallback content goes back inside the element, after
		// the generated form, so CSS that scopes to `challenge-form` still
		// reaches it and the document stays well-formed.
		return "<challenge-form" + attrs + ">" + challengeFormMarkup + m[3] + "</challenge-form>"
	})

	return injectTurnstileScript(out), found
}

// injectTurnstileScript adds the Turnstile API script to src, preferring the
// end of <head>, falling back to the start of <body>, and finally to just
// before the challenge form itself for a fragment with neither. A template
// that already loads api.js is left alone: loading it twice makes Turnstile
// render every widget on the page twice.
func injectTurnstileScript(src string) string {
	if loadsTurnstileScript(src) {
		return src
	}

	if loc := headCloseRE.FindStringIndex(src); loc != nil {
		return insertBefore(src, loc[0], turnstileScriptTag)
	}
	if loc := bodyOpenRE.FindStringIndex(src); loc != nil {
		return src[:loc[1]] + "\n" + turnstileScriptTag + src[loc[1]:]
	}
	if loc := challengeFormRE.FindStringIndex(src); loc != nil {
		return insertBefore(src, loc[0], turnstileScriptTag)
	}

	return src
}

// loadsTurnstileScript reports whether src already pulls in Cloudflare's
// api.js. It only counts the URL when it appears inside a <script> tag: a
// template that names the URL in a CSP <meta> tag or a comment isn't loading
// anything, and treating that as "the author has it covered" would leave the
// page with a widget that never renders.
func loadsTurnstileScript(src string) bool {
	for _, tag := range scriptTagRE.FindAllString(src, -1) {
		if strings.Contains(tag, turnstileAPISrc) {
			return true
		}
	}
	return false
}

// insertBefore splices snippet into src at idx, repeating whatever indentation
// the tag at idx had so the generated page still reads like the template its
// author wrote.
func insertBefore(src string, idx int, snippet string) string {
	var indent = src[strings.LastIndexByte(src[:idx], '\n')+1 : idx]
	if strings.TrimSpace(indent) != "" {
		indent = ""
	}
	return src[:idx] + snippet + "\n" + indent + src[idx:]
}

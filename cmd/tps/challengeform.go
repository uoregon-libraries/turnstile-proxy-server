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
const challengeFormMarkup = `
<form id="tps-challenge-form" action="{{.PostAction}}" method="POST">
  <input type="hidden" name="request_id" value="{{.RequestID}}" />
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
	// challengeFormRE matches a <challenge-form> placeholder: its opening tag,
	// its attributes, and an immediately following closing tag if there is one.
	// Anything else between the tags is left alone, so a template can keep
	// fallback content (a <noscript> block, say) inside the element.
	challengeFormRE = regexp.MustCompile(`(?is)<challenge-form\b([^>]*)>(\s*</challenge-form\s*>)?`)

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
		var attrs = challengeFormRE.FindStringSubmatch(match)[1]

		// Drop the slash of a self-closing <challenge-form />; we always write
		// an explicit closing tag. The rest of the attributes are preserved so
		// the element stays styleable (`challenge-form { ... }` or a class).
		attrs = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(attrs), "/"))
		if attrs != "" {
			attrs = " " + attrs
		}

		return "<challenge-form" + attrs + ">" + challengeFormMarkup + "</challenge-form>"
	})

	return injectTurnstileScript(out), found
}

// injectTurnstileScript adds the Turnstile API script to src, preferring the
// end of <head>, falling back to the start of <body>, and finally to just
// before the challenge form itself for a fragment with neither. A template
// that already loads api.js is left alone: loading it twice makes Turnstile
// render every widget on the page twice.
func injectTurnstileScript(src string) string {
	if strings.Contains(src, turnstileAPISrc) {
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

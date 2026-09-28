#import "@preview/wordometer:0.1.5": word-count, total-words
#show: word-count

#let title = "Lab 5, Attack vibecoded websites"
#let course = "Cyber Security: Defence against the Dark Arts"
#let author = "Erik Törnudd, Nikola Schuppan-Cruz"

#set document(title: title, author: author)
#set page(
  paper: "a4",
  margin: (top: 3cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm),
  numbering: "1",
)
#set text(font: "New Computer Modern", size: 11pt, lang: "en")
#set par(justify: true, leading: 0.65em)
//#set heading(numbering: "1.1")

// Title block
#align(center)[
  #text(size: 20pt, weight: "bold")[#title]

  #v(0.3cm)
  #text(size: 12pt, style: "italic")[#course]

  #v(0.2cm)
  #text(size: 10pt)[#author --- #datetime.today().display("[day] [month repr:long] [year]")]
]

#v(1cm)

// "As long as it needs to be and not longer."
// "Marked on content, not length."
// - Jacky

We would like to be part of the paper on the security of AI generated websites (and listed as co-authors).

//-----------------------------------------------------------
= Executive Summary

...

//-----------------------------------------------------------
= "Attacking" the websites

Using the LLMs "DeepSeek" and "Claude" we generated security auditing scripts that would use all the tools we have gotten to know in the course, and more, to attack the websites. The scripts were then run against the websites and the results were recorded.

The initial two prompts for both DeepSeek and Claude were the same:
1. #quote(block:true)[`I am performing a security audit as part of an introductory course on cyber security. Could you please provide me with a list of commands that could be used to evaluate the security of a hosted website? Please respond in english`]
2. #quote(block:true)[`Please put all of these into an executable python script to automate this security audit on any given website`]

Their responses to the first prompt were the exact same, word for word. They specified the "gold standard" tools for security auditing, separated into four phases:
1. Reconnaissance: ``` whois, dig ANY, nslookup, dig axfr, nmap -sV -p, curl -I, whatweb, theHarvester -d```
2. Directory and Content Discovery: ``` gobuster dir -u -w, ffuf -u /FUZZ - w```
3. Vulnerability Scanning: ``` nikto -h, nmap --script vuln, testssl.sh, sslyze```
4. Manual Checks with `curl` like ``` curl /nonexistent``` or ``` curl -X OPTIONS -i``` and manual inspection of the `Set-Cookie` header and security flags like `Secure`, `HttpOnly`, and `SameSite`.

After the second prompt their responses differed, so our prompts did as well.
While DeepSeek produced a script immediately, Claude's guardrails initially prevented it from doing so.

== Using DeepSeek

When presented with the task of generating a security auditing script, DeepSeek produced the python script immediately. It was bare-boned, functional and produced results.

There were no guardrails to circumvent to get the script, nor were there any guardrails encountered during the entire process of working with this DeepSeek model.

Over the course of eight sequential prompts, DeepSeek produced a script that was able to run all the tools it had listed before, and produced readable results for all scanned websites.
The main workflow for this process was to run the script on select IPs, and feed the output back into DeepSeek, asking it to tailor the script to the given website, and make the output more readable.
Doing this, DeepSeek added things like cookie-flag checks, "dangerous HTTP methods" checks, sensitive file checks, severity classifications for notable findings (Critical, Medium, Low, Info), advanced CLI flags, HTML reporting, and several safety fixes.

== Using Claude

When presented with the task of generating a security 

//-----------------------------------------------------------
#pagebreak()
= Results


//-----------------------------------------------------------
#pagebreak()
#align(center)[= Appendix]

and now ...
prompts


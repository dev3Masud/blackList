# Contributing to blackList

Thank you for your interest in contributing to the **blackList** repository! Your contributions help keep the lists clean, secure, and accurate for everyone.

Below are the guidelines for contributing to this project.

## How Can I Contribute?

### 1. Reporting False Positives (Whitelisting)
If a valid domain is blocked by our compiled lists:
* Open an issue in our repository.
* Select the **False Positive Report** template (if available) or create a blank issue.
* Provide the domain(s) and explain why it should be unblocked (e.g. valid business site, content distribution network).
* Once verified, we will add it to `whitelist.txt` to prevent it from being blocked.

### 2. Proposing New Threat Intel Feeds
If you know of a high-quality blocklist feed:
* Open an issue or submit a pull request.
* Propose the raw feed URL (must be txt/hosts format).
* Make sure it is maintained, active, and contains low rates of false positives.
* Recommend which category it belongs to (e.g., ads, malware, spam, phishing).

### 3. Improving Automation Scripts
If you want to optimize the compile scripts:
1. Fork this repository.
2. Create a feature branch: `git checkout -b feature/cool-optimization`
3. Commit your changes with descriptive commit messages.
4. Open a Pull Request referencing the issue or improvement.

---

## Code Style & Rules
* All Python automation code should follow standard formatting guidelines.
* Run scripts locally and verify they execute without errors before submitting.
* Ensure you do not hardcode credentials or active configuration keys in source files.

## Questions & Contact
For inquiries, suggestions, or general concerns, you can contact the maintainer at:
📧 **devmasud@proton.me**

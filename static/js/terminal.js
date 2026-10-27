/**
 * CloudGuard: AWS CLI & Attack Terminal Simulator
 * Implements interactive shell command line, command history (Arrow keys),
 * shortcut pills, and API execution against Python backend.
 */

class CloudTerminal {
  constructor(bodyId, inputId) {
    this.bodyEl = document.getElementById(bodyId);
    this.inputEl = document.getElementById(inputId);
    this.history = [];
    this.historyIndex = -1;

    if (this.inputEl) {
      this.bindEvents();
    }
    this.printWelcome();
  }

  printWelcome() {
    this.printLine('========================================================================', 'dim');
    this.printLine('  🛡️  CloudGuard Interactive AWS Security Shell v1.0.0', 'cyan');
    this.printLine('  Target: Capital One EC2 WAF & Amazon S3 Data Lake Infrastructure', 'muted');
    this.printLine('  Type "help" for a list of simulated commands or click the shortcuts above.', 'yellow');
    this.printLine('========================================================================\n', 'dim');
  }

  bindEvents() {
    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const cmd = this.inputEl.value.trim();
        if (cmd) {
          this.history.push(cmd);
          this.historyIndex = this.history.length;
          this.execute(cmd);
          this.inputEl.value = '';
        }
      } else if (e.key === 'ArrowUp') {
        if (this.history.length > 0 && this.historyIndex > 0) {
          this.historyIndex--;
          this.inputEl.value = this.history[this.historyIndex];
        }
      } else if (e.key === 'ArrowDown') {
        if (this.historyIndex < this.history.length - 1) {
          this.historyIndex++;
          this.inputEl.value = this.history[this.historyIndex];
        } else {
          this.historyIndex = this.history.length;
          this.inputEl.value = '';
        }
      }
    });

    // Quick Command Pills
    document.querySelectorAll('.cmd-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        const cmd = pill.getAttribute('data-cmd');
        if (cmd) {
          this.inputEl.value = cmd;
          this.inputEl.focus();
        }
      });
    });
  }

  async execute(command) {
    // Print user prompt line
    this.printLine(`attacker@cloudguard:~$ ${command}`, 'cyan');

    // Special local clear
    if (command.toLowerCase() === 'clear') {
      this.bodyEl.innerHTML = '';
      return;
    }

    try {
      const resp = await fetch('/api/terminal/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: json = JSON.stringify({ command: command })
      });
      const data = await resp.json();

      if (data.clear) {
        this.bodyEl.innerHTML = '';
        return;
      }

      if (data.output) {
        // Highlight AccessDenied vs Successful responses
        let style = 'normal';
        if (data.output.includes('AccessDenied') || data.output.includes('Forbidden') || data.output.includes('401')) {
          style = 'red';
        } else if (data.output.includes('s3://') || data.output.includes('Extracted') || data.output.includes('Success')) {
          style = 'green';
        } else if (data.output.includes('WARNING') || data.output.includes('CRITICAL')) {
          style = 'yellow';
        }

        this.printLine(data.output, style);
      }
    } catch (err) {
      this.printLine(`[ERROR] Communication failure with backend server: ${err.message}`, 'red');
    }

    // Scroll to bottom
    this.bodyEl.scrollTop = this.bodyEl.scrollHeight;
  }

  printLine(text, type = 'normal') {
    const div = document.createElement('div');
    div.style.marginBottom = '4px';
    div.style.whiteSpace = 'pre-wrap';

    if (type === 'cyan') div.style.color = '#38bdf8';
    else if (type === 'green') div.style.color = '#34d399';
    else if (type === 'red') div.style.color = '#f87171';
    else if (type === 'yellow') div.style.color = '#fbbf24';
    else if (type === 'dim') div.style.color = '#475569';
    else if (type === 'muted') div.style.color = '#94a3b8';
    else div.style.color = '#e2e8f0';

    div.textContent = text;
    this.bodyEl.appendChild(div);
    this.bodyEl.scrollTop = this.bodyEl.scrollHeight;
  }
}

window.CloudTerminal = CloudTerminal;

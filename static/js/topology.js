/**
 * CloudGuard: Interactive Cloud Architecture Topology Visualizer
 * Renders nodes: Attacker -> EC2 WAF -> IMDS 169.254.169.254 -> IAM/STS -> S3 Buckets
 * Animates live network traffic, firewall shield barriers, and breach exploitation paths.
 */

class CloudTopology {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.nodes = [];
    this.links = [];
    this.particles = [];
    this.activeStep = 0;
    this.selectedNode = null;
    this.animationFrameId = null;
    
    this.resizeCanvas();
    window.addEventListener('resize', () => this.resizeCanvas());
    
    this.initNodes();
    this.bindEvents();
    this.startAnimationLoop();
  }

  resizeCanvas() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width;
    this.canvas.height = rect.height || 480;
    if (this.nodes.length) {
      this.layoutNodes();
    }
  }

  initNodes() {
    this.nodes = [
      {
        id: 'attacker',
        label: 'External Attacker',
        subtext: 'IP: 198.51.100.42 (Public Web)',
        icon: '🥷',
        color: '#ef4444',
        status: 'active',
        type: 'threat',
        details: 'Attacker initiating SSRF reconnaissance against publicly exposed web tier.'
      },
      {
        id: 'waf_ec2',
        label: 'EC2: ModSecurity WAF',
        subtext: 'Instance: i-0b73c21a9 (Public Subnet)',
        icon: '🖥️',
        color: '#38bdf8',
        status: 'normal',
        type: 'compute',
        details: 'Reverse proxy server running open-source WAF. Misconfigured proxy forwards unsanitized requests.'
      },
      {
        id: 'imds',
        label: 'AWS IMDS (Metadata)',
        subtext: 'Link-Local: 169.254.169.254',
        icon: '📡',
        color: '#f59e0b',
        status: 'normal',
        type: 'metadata',
        details: 'EC2 Instance Metadata Service. In IMDSv1, plain GET requests return temporary IAM role STS credentials.'
      },
      {
        id: 'iam_sts',
        label: 'AWS IAM & STS Service',
        subtext: 'Role: app-waf-production-role',
        icon: '🔑',
        color: '#a855f7',
        status: 'normal',
        type: 'identity',
        details: 'Security Token Service generating temporary credentials with attached IAM policies.'
      },
      {
        id: 's3_bucket',
        label: 'Amazon S3: Credit Apps',
        subtext: 's3://c1-prod-credit-applications',
        icon: '🪣',
        color: '#10b981',
        status: 'normal',
        type: 'storage',
        details: 'Customer credit application data lake containing 106M confidential records, SSNs, and credit limits.'
      }
    ];

    this.links = [
      { from: 'attacker', to: 'waf_ec2', label: '1. Inbound HTTP', active: true },
      { from: 'waf_ec2', to: 'imds', label: '2. SSRF /meta-data', active: false },
      { from: 'imds', to: 'iam_sts', label: '3. STS Token Broker', active: false },
      { from: 'attacker', to: 's3_bucket', label: '4. Direct S3 Exfiltration', active: false }
    ];

    this.layoutNodes();
  }

  layoutNodes() {
    const w = this.canvas.width;
    const h = this.canvas.height;
    
    // Position nodes in a clear, readable cloud architecture flow
    const nodeMap = {
      attacker: { x: w * 0.12, y: h * 0.5 },
      waf_ec2: { x: w * 0.38, y: h * 0.32 },
      imds: { x: w * 0.65, y: h * 0.32 },
      iam_sts: { x: w * 0.88, y: h * 0.32 },
      s3_bucket: { x: w * 0.65, y: h * 0.76 }
    };

    this.nodes.forEach(n => {
      if (nodeMap[n.id]) {
        n.x = nodeMap[n.id].x;
        n.y = nodeMap[n.id].y;
        n.radius = 36;
      }
    });
  }

  bindEvents() {
    this.canvas.addEventListener('click', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      let found = null;
      for (const node of this.nodes) {
        const dist = Math.hypot(node.x - clickX, node.y - clickY);
        if (dist <= node.radius + 6) {
          found = node;
          break;
        }
      }
      this.selectedNode = found;
      if (found && window.CloudGuardApp) {
        window.CloudGuardApp.showNodeDetails(found);
      }
    });
  }

  triggerStepAnimation(stepIndex, isSecured) {
    this.activeStep = stepIndex;
    this.particles = [];

    // Trigger visual traffic particles corresponding to current breach step
    if (stepIndex === 1) {
      // Step 1: Attacker -> WAF -> IMDS
      this.spawnParticle('attacker', 'waf_ec2', isSecured ? '#10b981' : '#ef4444');
      if (!isSecured) {
        setTimeout(() => this.spawnParticle('waf_ec2', 'imds', '#ef4444'), 600);
      }
    } else if (stepIndex === 2) {
      // Step 2: IMDS -> IAM STS -> Attacker
      this.spawnParticle('imds', 'iam_sts', isSecured ? '#10b981' : '#ef4444');
      if (!isSecured) {
        setTimeout(() => this.spawnParticle('iam_sts', 'attacker', '#f59e0b'), 600);
      }
    } else if (stepIndex === 3) {
      // Step 3: Attacker queries S3
      this.spawnParticle('attacker', 's3_bucket', isSecured ? '#10b981' : '#ef4444');
    } else if (stepIndex === 4) {
      // Step 4: S3 Exfiltration
      if (!isSecured) {
        this.spawnParticle('s3_bucket', 'attacker', '#ef4444', 15);
      } else {
        this.spawnParticle('attacker', 's3_bucket', '#10b981', 4);
      }
    }
  }

  spawnParticle(fromId, toId, color, count = 1) {
    const fromNode = this.nodes.find(n => n.id === fromId);
    const toNode = this.nodes.find(n => n.id === toId);
    if (!fromNode || !toNode) return;

    for (let i = 0; i < count; i++) {
      this.particles.push({
        fromX: fromNode.x,
        fromY: fromNode.y,
        toX: toNode.x,
        toY: toNode.y,
        progress: - (i * 0.15),
        color: color,
        speed: 0.018 + (Math.random() * 0.005)
      });
    }
  }

  startAnimationLoop() {
    const render = () => {
      this.draw();
      this.animationFrameId = requestAnimationFrame(render);
    };
    render();
  }

  draw() {
    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;
    const isSecured = window.CloudGuardApp ? window.CloudGuardApp.state.scenario === 'secured' : false;

    // Clear background
    ctx.clearRect(0, 0, w, h);

    // Draw Subtle Cyber Grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Draw VPC Cloud Boundary Boundary Box
    ctx.save();
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.18)';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([6, 6]);
    ctx.strokeRect(w * 0.28, h * 0.12, w * 0.69, h * 0.80);
    ctx.fillStyle = 'rgba(0, 240, 255, 0.6)';
    ctx.font = '11px JetBrains Mono, monospace';
    ctx.fillText('AWS Cloud Boundary (VPC: vpc-c1-production-east1)', w * 0.30, h * 0.16);
    ctx.restore();

    // Draw Links / Connections
    this.links.forEach(link => {
      const fromNode = this.nodes.find(n => n.id === link.from);
      const toNode = this.nodes.find(n => n.id === link.to);
      if (!fromNode || !toNode) return;

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(fromNode.x, fromNode.y);
      ctx.lineTo(toNode.x, toNode.y);

      // Color link based on threat level
      if (link.to === 's3_bucket' && link.from === 'attacker') {
        ctx.strokeStyle = isSecured ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.45)';
        ctx.setLineDash([4, 4]);
      } else {
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
      }
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.restore();

      // Label along connection
      const midX = (fromNode.x + toNode.x) / 2;
      const midY = (fromNode.y + toNode.y) / 2;
      ctx.save();
      ctx.fillStyle = 'rgba(148, 163, 184, 0.8)';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(link.label, midX, midY - 8);
      ctx.restore();
    });

    // Draw Live Particles
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.progress += p.speed;

      if (p.progress >= 0 && p.progress <= 1) {
        const curX = p.fromX + (p.toX - p.fromX) * p.progress;
        const curY = p.fromY + (p.toY - p.fromY) * p.progress;

        ctx.save();
        ctx.beginPath();
        ctx.arc(curX, curY, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 10;
        ctx.fill();
        ctx.restore();
      }

      if (p.progress > 1) {
        this.particles.splice(i, 1);
      }
    }

    // Draw Defense Barriers / Shields if Secured
    if (isSecured) {
      const waf = this.nodes.find(n => n.id === 'waf_ec2');
      const imds = this.nodes.find(n => n.id === 'imds');
      const s3 = this.nodes.find(n => n.id === 's3_bucket');

      // Shield on WAF (SSRF Filter)
      if (waf) {
        this.drawShieldBadge(waf.x + 28, waf.y - 28, '🛡️ SSRF Block');
      }
      // Shield on IMDS (IMDSv2 Token)
      if (imds) {
        this.drawShieldBadge(imds.x + 28, imds.y - 28, '🛡️ IMDSv2');
      }
      // Shield on S3 (Least Privilege & VPCE)
      if (s3) {
        this.drawShieldBadge(s3.x + 28, s3.y - 28, '🛡️ Deny s3:*');
      }
    }

    // Draw Nodes
    this.nodes.forEach(node => {
      ctx.save();

      // Selected ring
      if (this.selectedNode && this.selectedNode.id === node.id) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 8, 0, Math.PI * 2);
        ctx.strokeStyle = '#00f0ff';
        ctx.lineWidth = 2;
        ctx.shadowColor = '#00f0ff';
        ctx.shadowBlur = 15;
        ctx.stroke();
      }

      // Outer glow circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle = '#111827';
      ctx.shadowColor = node.color;
      ctx.shadowBlur = 12;
      ctx.fill();

      // Border ring
      ctx.strokeStyle = node.color;
      ctx.lineWidth = 2.5;
      ctx.stroke();

      // Node Icon
      ctx.font = '22px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(node.icon, node.x, node.y);

      // Node Label
      ctx.fillStyle = '#f8fafc';
      ctx.font = 'bold 12px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + node.radius + 18);

      // Node Subtext
      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.fillText(node.subtext, node.x, node.y + node.radius + 32);

      ctx.restore();
    });
  }

  drawShieldBadge(x, y, text) {
    const ctx = this.ctx;
    ctx.save();
    ctx.fillStyle = 'rgba(16, 185, 129, 0.9)';
    ctx.strokeStyle = '#34d399';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(x - 4, y - 10, 85, 20, 6);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 9px JetBrains Mono, monospace';
    ctx.textAlign = 'left';
    ctx.fillText(text, x + 2, y + 3);
    ctx.restore();
  }
}

window.CloudTopology = CloudTopology;

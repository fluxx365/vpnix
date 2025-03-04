#!/bin/bash

# Xray VPN with Nginx Setup Script
# This script automates the installation and configuration of Xray VPN server with Nginx

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check for domain argument or prompt for it
if [ -z "$1" ]; then
    read -p "Enter your domain name: " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo "Domain name is required"
        exit 1
    fi
else
    DOMAIN="$1"
fi

# Default configuration paths
XRAY_CONFIG_DIR="/usr/local/etc/xray"
NGINX_CONFIG_DIR="/etc/nginx/conf.d"
NGINX_XRAY_CONF="$NGINX_CONFIG_DIR/xray.conf"
HTML_ROOT="/var/www/html"

# UUID generation for security
UUID=$(cat /proc/sys/kernel/random/uuid)
echo "Generated UUID: $UUID"

# Function to check and install packages
install_dependencies() {
    echo "Installing dependencies..."
    
    # Detect OS
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y nginx certbot python3-certbot-nginx curl socat
    elif [ -f /etc/redhat-release ]; then
        # CentOS/RHEL
        yum install -y epel-release
        yum install -y nginx certbot python3-certbot-nginx curl socat
    else
        echo "Unsupported distribution. Installing required packages manually..."
        # Try to install nginx anyway
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y nginx certbot python3-certbot-nginx curl socat
        elif command -v yum &> /dev/null; then
            yum install -y epel-release nginx certbot python3-certbot-nginx curl socat
        else
            echo "Could not determine package manager. Please install Nginx and Certbot manually."
            exit 1
        fi
    fi
    
    # Create web root directory if it doesn't exist
    mkdir -p /var/www/html
    
    # Enable and start Nginx
    systemctl enable nginx
    systemctl start nginx
    
    echo "Dependencies installed successfully"
}

# Function to install Xray
install_xray() {
    echo "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
    echo "Xray installed successfully"
}

# Function to create HTML landing page
create_html_landing_page() {
    echo "Creating HTML landing page..."
    
    # Create HTML directory if it doesn't exist
    mkdir -p "$HTML_ROOT"
    
    # Current date values for the template
    CURRENT_YEAR=$(date +"%Y")
    CURRENT_DATE=$(date +"%B %d, %Y")
    
    # Create index.html with customized values
    cat > "$HTML_ROOT/index.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to $DOMAIN</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            width: 80%;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
        }
        header {
            background-color: #0066cc;
            color: white;
            padding: 2rem 0;
            text-align: center;
            margin-bottom: 2rem;
            border-radius: 0 0 10px 10px;
        }
        .logo {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0;
        }
        .tagline {
            font-style: italic;
            margin: 0.5rem 0 0;
            opacity: 0.9;
        }
        .content {
            background-color: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h2 {
            color: #0066cc;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 0.5rem;
        }
        .feature {
            margin-bottom: 1.5rem;
        }
        .feature h3 {
            margin-bottom: 0.5rem;
            color: #444;
        }
        footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem 0;
            font-size: 0.9rem;
            color: #666;
        }
        .status {
            background-color: #dff0d8;
            padding: 0.5rem;
            border-radius: 5px;
            margin-top: 2rem;
            text-align: center;
            color: #3c763d;
        }
        @media (max-width: 768px) {
            .container {
                width: 95%;
                padding: 1rem;
            }
            header {
                padding: 1.5rem 0;
            }
            .logo {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1 class="logo">$DOMAIN</h1>
            <p class="tagline">Welcome to our web server</p>
        </div>
    </header>

    <div class="container">
        <div class="content">
            <h2>About Us</h2>
            <p>This server is running successfully and is ready to provide high-quality services. We prioritize security, performance, and reliability in everything we do.</p>
            
            <h2>Our Services</h2>
            <div class="feature">
                <h3>High Performance</h3>
                <p>Our infrastructure is designed for optimal performance, ensuring fast and reliable connections.</p>
            </div>
            
            <div class="feature">
                <h3>Security First</h3>
                <p>We implement industry-standard security practices to protect our services and your data.</p>
            </div>
            
            <div class="feature">
                <h3>24/7 Uptime</h3>
                <p>Our systems are monitored constantly to ensure maximum availability.</p>
            </div>
            
            <div class="status">
                ✓ Server is operational and running normally
            </div>
        </div>
        
        <footer>
            <p>&copy; $CURRENT_YEAR $DOMAIN - All Rights Reserved</p>
            <p>Last updated: $CURRENT_DATE</p>
        </footer>
    </div>
</body>
</html>
EOF

    # Set proper permissions
    chmod 644 "$HTML_ROOT/index.html"
    
    echo "HTML landing page created successfully"
}

# Function to create Xray configurations
create_xray_configs() {
    echo "Creating Xray configurations..."
    
    # Create Xray config directory if it doesn't exist
    mkdir -p "$XRAY_CONFIG_DIR"
    
    # Create config.json for TLS (port 443)
    cat > "$XRAY_CONFIG_DIR/config.json" << EOF
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [
    {
      "port": 20001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      }
    },
    {
      "port": 20002,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "level": 0,
            "email": "user@example.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        }
      }
    },
    {
      "port": 20003,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${UUID}",
            "email": "user@example.com"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
    
    # Create none.json for non-TLS (port 80)
    cat > "$XRAY_CONFIG_DIR/none.json" << EOF
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      }
    },
    {
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "level": 0,
            "email": "user@example.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

    # Set proper permissions
    chmod 644 "$XRAY_CONFIG_DIR/config.json"
    chmod 644 "$XRAY_CONFIG_DIR/none.json"
    
    echo "Xray configurations created successfully"
}

# Function to create Nginx configuration
create_nginx_config() {
    echo "Creating Nginx configuration..."
    
    # Create initial HTTP-only configuration
    cat > "$NGINX_XRAY_CONF" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    # HTTP WebSocket paths - Don't redirect these to HTTPS
    location /vmess-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vless-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        root /var/www/html;
        index index.html index.htm;
    }
}
EOF

    # Set proper permissions
    chmod 644 "$NGINX_XRAY_CONF"
    
    echo "Nginx configuration created successfully"
}

# Function to obtain SSL certificate
obtain_ssl_cert() {
    echo "Obtaining SSL certificate for $DOMAIN..."
    
    # Restart Nginx to apply new configuration
    systemctl restart nginx
    
    # Use certbot to obtain certificate
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" --redirect
    
    # Check if certificate was obtained successfully
    if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        echo "Failed to obtain SSL certificate. Check the error messages above."
        return 1
    fi
    
    # Add HTTPS server block if it doesn't exist yet
    if ! grep -q "listen 443 ssl http2" "$NGINX_XRAY_CONF"; then
        cat >> "$NGINX_XRAY_CONF" << EOF

# HTTPS Server Block
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HTTPS WebSocket paths
    location /vmess-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vless-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        root /var/www/html;
        index index.html index.htm;
    }
}
EOF
    fi
    
    # Test and reload Nginx
    nginx -t
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo "SSL certificate installed successfully"
    else
        echo "Nginx configuration test failed. Please check the error messages above."
        return 1
    fi
    
    return 0
}

# Function to set up systemd service files for Xray
setup_xray_services() {
    echo "Setting up Xray services..."
    
    # Create systemd service for Xray TLS (config.json)
    cat > /etc/systemd/system/xray@.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/%i.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start Xray services
    systemctl enable xray
    systemctl start xray
    systemctl enable xray@none
    systemctl start xray@none
    
    echo "Xray services set up successfully"
}

# Function to generate connection links for clients
generate_link() {
    echo "Generating connection links..."
    
    # Create config directory if it doesn't exist
    mkdir -p /usr/local/etc/xray/config
    
    # Create VMess TLS config file
    cat > /usr/local/etc/xray/config/vmess-tls.json << EOF
{
    "v": "2",
    "ps": "${DOMAIN}-TLS",
    "add": "${DOMAIN}",
    "port": "443",
    "id": "${UUID}",
    "aid": "0",
    "net": "ws",
    "path": "/vmess-ws",
    "type": "none",
    "host": "${DOMAIN}",
    "tls": "tls"
}
EOF

    # Create VMess non-TLS config file
    cat > /usr/local/etc/xray/config/vmess-none.json << EOF
{
    "v": "2",
    "ps": "${DOMAIN}-HTTP",
    "add": "${DOMAIN}",
    "port": "80",
    "id": "${UUID}",
    "aid": "0",
    "net": "ws",
    "path": "/vmess-ws",
    "type": "none",
    "host": "${DOMAIN}",
    "tls": "none"
}
EOF

    # Generate base64 encoded VMess links
    VMESS_LINK_TLS="vmess://$(base64 -w 0 /usr/local/etc/xray/config/vmess-tls.json)"
    VMESS_LINK_NONE="vmess://$(base64 -w 0 /usr/local/etc/xray/config/vmess-none.json)"

    # Generate VLESS links
    VLESS_LINK_TLS="vless://${UUID}@${DOMAIN}:443?path=/vless-ws&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${DOMAIN}-TLS"
    VLESS_LINK_NONE="vless://${UUID}@${DOMAIN}:80?path=/vless-ws&encryption=none&host=${DOMAIN}&type=ws#${DOMAIN}-HTTP"

    # Generate Trojan link (TLS only)
    TROJAN_LINK_TLS="trojan://${UUID}@${DOMAIN}:443?path=/trojan-ws&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${DOMAIN}-TLS"
}

# Function to display configuration summary
display_summary() {
    # Run generate_link function to create connection URLs
    generate_link
    
    echo "=============================================="
    echo "          Xray VPN Setup Complete             "
    echo "=============================================="
    echo "Domain:           $DOMAIN"
    echo "UUID:             $UUID"
    echo "=============================================="
    echo "VMess WebSocket (TLS):"
    echo "  - Address:      $DOMAIN"
    echo "  - Port:         443"
    echo "  - UUID:         $UUID"
    echo "  - Path:         /vmess-ws"
    echo "  - TLS:          On"
    echo ""
    echo "  Connection Link:"
    echo "  $VMESS_LINK_TLS"
    echo "=============================================="
    echo "VMess WebSocket (non-TLS):"
    echo "  - Address:      $DOMAIN"
    echo "  - Port:         80"
    echo "  - UUID:         $UUID"
    echo "  - Path:         /vmess-ws"
    echo "  - TLS:          Off"
    echo ""
    echo "  Connection Link:"
    echo "  $VMESS_LINK_NONE"
    echo "=============================================="
    echo "VLESS WebSocket (TLS):"
    echo "  - Address:      $DOMAIN"
    echo "  - Port:         443"
    echo "  - UUID:         $UUID"
    echo "  - Path:         /vless-ws"
    echo "  - TLS:          On"
    echo ""
    echo "  Connection Link:"
    echo "  $VLESS_LINK_TLS"
    echo "=============================================="
    echo "VLESS WebSocket (non-TLS):"
    echo "  - Address:      $DOMAIN"
    echo "  - Port:         80"
    echo "  - UUID:         $UUID"
    echo "  - Path:         /vless-ws"
    echo "  - TLS:          Off"
    echo ""
    echo "  Connection Link:"
    echo "  $VLESS_LINK_NONE"
    echo "=============================================="
    echo "Trojan WebSocket (TLS only):"
    echo "  - Address:      $DOMAIN"
    echo "  - Port:         443"
    echo "  - Password:     $UUID"
    echo "  - Path:         /trojan-ws"
    echo "  - TLS:          On"
    echo ""
    echo "  Connection Link:"
    echo "  $TROJAN_LINK_TLS"
    echo "=============================================="
    echo "Configuration files:"
    echo "  - Xray TLS:     $XRAY_CONFIG_DIR/config.json"
    echo "  - Xray non-TLS: $XRAY_CONFIG_DIR/none.json"
    echo "  - Nginx:        $NGINX_XRAY_CONF"
    echo "=============================================="
    
    # Save links to a file for future reference
    echo "Saving connection links to /root/xray_links.txt"
    cat > /root/xray_links.txt << EOF
==== Xray VPN Connection Links ====
Domain: $DOMAIN
Date: $(date)

==== VMess TLS ====
$VMESS_LINK_TLS

==== VMess Non-TLS ====
$VMESS_LINK_NONE

==== VLESS TLS ====
$VLESS_LINK_TLS

==== VLESS Non-TLS ====
$VLESS_LINK_NONE

==== Trojan TLS ====
$TROJAN_LINK_TLS
EOF
}

finishing() {
    cat > "$NGINX_XRAY_CONF" << EOF
# HTTPS Server Block
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HTTPS WebSocket paths
    location /vmess-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vless-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        root /var/www/html;
        index index.html index.htm;
    }
}

# HTTP Server Block - Allow WebSocket connections but redirect normal traffic to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    # HTTP WebSocket paths - Don't redirect these to HTTPS
    location /vmess-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vless-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Redirect normal web traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
systemctl restart nginx
}

# Main installation process
main() {
    echo "Starting Xray VPN with Nginx installation for domain: $DOMAIN"
    
    install_dependencies
    install_xray
    create_xray_configs
    create_html_landing_page
    create_nginx_config
    obtain_ssl_cert
    setup_xray_services
    
    # Final Nginx test and reload
    nginx -t && systemctl reload nginx
    
    # Display configuration summary
    display_summary
    finishing
}

# Start the installation process
main

exit 0

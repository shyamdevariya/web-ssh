const express = require('express');
const cors = require('cors');
const { generateKeyPair } = require('crypto');
const { Client } = require('ssh2');
const WebSocket = require('ws');
const http = require('http');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
const WS_PORT = 3001;

// In-memory hosts store
// Each host: { id, name, host, port, username, authMethod ('password' or 'privateKey'), password?, privateKey? }
const hosts = [];
let hostIdCounter = 1;

// Generate SSH Key Pair API
app.post('/api/generate-key', (req, res) => {
  generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  }, (err, publicKey, privateKey) => {
    if (err) {
      res.status(500).json({ error: 'Key generation failed' });
      return;
    }
    res.json({ publicKey, privateKey });
  });
});

// Hosts CRUD

// Get all hosts
app.get('/api/hosts', (req, res) => {
  // Don't send privateKey or password in list response for security
  const safeHosts = hosts.map(({id, name, host, port, username, authMethod}) => ({
    id, name, host, port, username, authMethod
  }));
  res.json(safeHosts);
});

// Add new host
app.post('/api/hosts', (req, res) => {
  const { name, host, port, username, authMethod, password, privateKey } = req.body;
  if (!name || !host || !port || !username || !authMethod) {
    res.status(400).json({ error: 'Missing required fields' });
    return;
  }
  if (authMethod === 'password' && !password) {
    res.status(400).json({ error: 'Password required for password auth' });
    return;
  }
  if (authMethod === 'privateKey' && !privateKey) {
    res.status(400).json({ error: 'Private key required for privateKey auth' });
    return;
  }
  const newHost = {
    id: hostIdCounter++,
    name,
    host,
    port,
    username,
    authMethod,
    password: authMethod === 'password' ? password : undefined,
    privateKey: authMethod === 'privateKey' ? privateKey : undefined
  };
  hosts.push(newHost);
  res.json({ success: true, host: newHost });
});

// Delete host
app.delete('/api/hosts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const index = hosts.findIndex(h => h.id === id);
  if (index === -1) {
    res.status(404).json({ error: 'Host not found' });
    return;
  }
  hosts.splice(index, 1);
  res.json({ success: true });
});

// HTTP server for WebSocket upgrade
const server = http.createServer(app);

// WebSocket server for terminal
const wss = new WebSocket.Server({ server, path: '/ws/terminal' });

// For each WebSocket connection, do SSH connection and pipe data
wss.on('connection', (ws) => {
  let sshClient = new Client();
  let sshStream = null;

  ws.on('message', (message) => {
    // Messages are JSON strings for initial auth or raw data for terminal input
    if (typeof message === 'string') {
      try {
        const data = JSON.parse(message);
        if (data.type === 'start-ssh') {
          // Start SSH connection with given config
          const { host, port, username, authMethod, password, privateKey } = data;
          sshClient.on('ready', () => {
            ws.send(JSON.stringify({ type: 'status', status: 'SSH connection ready' }));
            sshClient.shell((err, stream) => {
              if (err) {
                ws.send(JSON.stringify({ type: 'error', message: 'SSH shell error: ' + err.message }));
                sshClient.end();
                return;
              }
              sshStream = stream;
              sshStream.on('data', (chunk) => {
                ws.send(JSON.stringify({ type: 'data', data: chunk.toString('utf-8') }));
              });
              sshStream.on('close', () => {
                ws.send(JSON.stringify({ type: 'status', status: 'SSH session ended' }));
                sshClient.end();
              });
              sshStream.stderr.on('data', (chunk) => {
                ws.send(JSON.stringify({ type: 'data', data: chunk.toString('utf-8') }));
              });
            });
          }).on('close', () => {
            ws.send(JSON.stringify({ type: 'status', status: 'SSH connection closed' }));
          }).on('error', (err) => {
            ws.send(JSON.stringify({ type: 'error', message: 'SSH connection error: ' + err.message }));
          });

          let connectionConfig = {
            host,
            port: Number(port),
            username,
            readyTimeout: 20000, // 20 seconds timeout
          };
          if (authMethod === 'password') {
            connectionConfig.password = password;
          } else if (authMethod === 'privateKey') {
            connectionConfig.privateKey = privateKey;
          }

          sshClient.connect(connectionConfig);
        }
      } catch (err) {
        // Not JSON - treat as terminal input
        if (sshStream) {
          sshStream.write(message);
        }
      }
    } else {
      // Binary message likely terminal input
      if (sshStream) {
        sshStream.write(message);
      }
    }
  });

  ws.on('close', () => {
    if (sshClient) {
      sshClient.end();
    }
  });
});

server.listen(PORT, () => {
  console.log(`HTTP API server listening on http://localhost:${PORT}`);
});

const path = require('path');
const fs = require('node:fs/promises');
const { Wallets, Gateway } = require('fabric-network');
const { TextEncoder } = require('node:util');
const { split } = require('shamir');
const crypto = require('crypto');
const { performance } = require('perf_hooks');

// Configuration
const CHANNEL_NAME = 'sipfs';
const CHAINCODE_NAME = 'basic';
const USERNAME = 'dd1'; // Data Owner username
const WALLET_PATH = path.join(__dirname, 'walletOwner');
const CCP_PATH = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  'test-network',
  'organizations',
  'peerOrganizations',
  'org1.example.com',
  'connection-org1.json'
);

// Utility functions
function generateRandomAccessKey(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

function hashKeyValuePairs(policyAttributes) {
  const hashedAttributes = [];
  for (const attribute of policyAttributes) {
    for (const key in attribute) {
      if (attribute.hasOwnProperty(key)) {
        const value = attribute[key];
        const concatenated = `${key}:${JSON.stringify(value)}`;
        const combinedHash = crypto.createHash('sha256').update(concatenated).digest('hex');
        hashedAttributes.push({ [key]: value, hash: combinedHash });
      }
    }
  }
  return hashedAttributes;
}

function encrypt(text, symmetricKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(symmetricKey), iv);
  let encrypted = cipher.update(text, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText, symmetricKey) {
  const textParts = encryptedText.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedData = textParts.join(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(symmetricKey), iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return decrypted;
}

function generateUniqueId(prefix) {
  return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

// Attribute pools for random generation
const ATTRIBUTE_POOLS = {
  department: ['engineering', 'finance', 'hr', 'marketing', 'sales', 'it', 'research'],
  role: ['developer', 'manager', 'analyst', 'designer', 'engineer', 'consultant', 'admin'],
  location: ['us', 'eu', 'asia', 'africa', 'australia', 'south_america'],
  skills: ['python', 'java', 'sql', 'javascript', 'cloud', 'devops', 'ai', 'blockchain'],
  clearance: ['public', 'confidential', 'secret', 'top_secret'],
  interest: ['tech', 'finance', 'health', 'education', 'sports', 'music', 'art'],
  languages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko']
};

// Randomly select n items from an array
function getRandomSubset(array, n) {
  const shuffled = array.sort(() => 0.5 - Math.random());
  return shuffled.slice(0, Math.min(n, array.length));
}

// Generate a single random policy attribute with varied keys
function generateRandomPolicyAttribute() {
  const numKeys = Math.floor(Math.random() * 3) + 2; // 2-4 keys per attribute
  const availableKeys = Object.keys(ATTRIBUTE_POOLS);
  const selectedKeys = getRandomSubset(availableKeys, numKeys);
  const attribute = {};
  
  selectedKeys.forEach(key => {
    const numValues = Math.floor(Math.random() * 2) + 1; // 1-2 values per key
    attribute[key] = getRandomSubset(ATTRIBUTE_POOLS[key], numValues);
  });
  
  return attribute;
}

// Generate user PolicySet with diverse attributes
function generateUserPolicySet(attributeCount, includeRequired = false) {
  const attributes = [];
  
  // Required attributes for asset.policySet and promoteAttributes
  const requiredAttribute = {
    interest: ['department:engineering', 'role:developer'],
    languages: ['skills:python']
  };
  
  // If includeRequired, add the required attribute
  if (includeRequired) {
    attributes.push(requiredAttribute);
  }
  
  // Fill remaining attributes with random ones
  for (let i = attributes.length; i < attributeCount; i++) {
    attributes.push(generateRandomPolicyAttribute());
  }
  
  // Shuffle to avoid predictable placement
  return JSON.stringify(attributes.sort(() => 0.5 - Math.random()));
}

function generateShamirFragments(secret, parts, quorum) {
  const utf8Encoder = new TextEncoder();
  const secretBytes = utf8Encoder.encode(secret);
  const shares = split(crypto.randomBytes, parts, quorum, secretBytes);

  const policyAttributes = Array.from({ length: parts }, (_, i) => ({
    interest: [`topic${i + 1}`],
    languages: ['en'],
  }));

  const hashedAttributes = hashKeyValuePairs(policyAttributes);

  const fragmentsMap = hashedAttributes.slice(0, parts).map((attr, index) => ({
    ...attr,
    share: shares[index + 1],
  }));

  return { fragmentsMap, hashedAttributes };
}

async function connectToUserGateway(username, userType) {
  let ccpPath;
  let walletPath;
  if (userType === 'requester') {
    walletPath = path.join(__dirname, 'walletRequester');
    ccpPath = path.resolve(
      __dirname,
      '..',
      '..',
      '..',
      'test-network',
      'organizations',
      'peerOrganizations',
      'org2.example.com',
      'connection-org2.json'
    );
  } else if (userType === 'owner') {
    walletPath = WALLET_PATH;
    ccpPath = CCP_PATH;
  } else {
    throw new Error(`Invalid userType: ${userType}`);
  }

  const wallet = await Wallets.newFileSystemWallet(walletPath);
  const identity = await wallet.get(username);
  if (!identity) {
    throw new Error(`An identity for the user ${username} does not exist in the wallet`);
  }

  const ccp = JSON.parse(await fs.readFile(ccpPath, 'utf8'));
  const gateway = new Gateway();

  await gateway.connect(ccp, {
    wallet,
    identity: username,
    discovery: { enabled: true, asLocalhost: true },
    eventHandlerOptions: {
      commitTimeout: 10000,
      endorseTimeout: 10000,
    },
    connectionTimeout: 1200000,
    clientConfig: {
      'grpc.keepalive_time_ms': 10000,
      'grpc.keepalive_timeout_ms': 20000,
      'grpc.http2.max_pings_without_data': 0,
    },
  });
  return gateway;
}

async function setupTestData(contract) {
  console.log('Setting up test data for benchmarks...');
  const assetId = generateUniqueId('asset');
  const userId = generateUniqueId('user');
  const currentDate = new Date().toISOString();

  try {
    // Check if user exists and create if not
    let userExists;
    try {
      const userExistsResult = await contract.evaluateTransaction('UserExists', userId);
      userExists = userExistsResult ? JSON.parse(userExistsResult.toString()) : false;
    } catch (error) {
      console.error(`Error checking if user ${userId} exists:`, error.message);
      userExists = false;
    }
    if (!userExists) {
      const policySet = generateUserPolicySet(1, true); // Start with minimal attributes, include required
      await contract.submitTransaction(
        'CreateUser',
        userId,
        'requester',
        currentDate,
        'dummy-public-key',
        policySet
      );
      console.log(`User ${userId} created successfully`);
      try {
        const userResult = await contract.evaluateTransaction('GetUser', userId);
        const user = JSON.parse(userResult.toString());
        console.log(`Created user:`, user);
      } catch (error) {
        console.error(`Error reading created user ${userId}:`, error.message);
      }
    } else {
      console.log(`User ${userId} already exists, skipping creation`);
    }

    // Check if asset exists and delete if it does
    let assetExists;
    try {
      const assetExistsResult = await contract.evaluateTransaction('AssetExists', assetId);
      assetExists = assetExistsResult ? JSON.parse(assetExistsResult.toString()) : false;
    } catch (error) {
      console.error(`Error checking if asset ${assetId} exists:`, error.message);
      assetExists = false;
    }
    if (assetExists) {
      console.log(`Asset ${assetId} already exists, deleting...`);
      await contract.submitTransaction('DeleteAsset', assetId);
      console.log(`Asset ${assetId} deleted successfully`);
    }

    // Create test asset with specific policySet and promoteAttributes
    const metaData = JSON.stringify({ description: 'Test asset for promotion' });
    const policySet = JSON.stringify([
      {
        interest: ['department:engineering', 'role:developer'],
        languages: ['skills:python']
      }
    ]);
    const promoteAttributes = JSON.stringify([
      {
        interest: ['department:engineering', 'role:developer'],
        languages: ['skills:python']
      }
    ]);
    const publicKeyOwner = 'pubkey123';
    const name = 'TestAsset';
    const cid = 'cid123';
    const prevCid = '';
    const key = generateRandomAccessKey();
    const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
    const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

    await contract.submitTransaction(
      'CreateAsset',
      assetId,
      metaData,
      policySet,
      publicKeyOwner,
      currentDate,
      currentDate,
      USERNAME,
      name,
      cid,
      prevCid,
      hashAccessKey,
      JSON.stringify(fragmentsMap),
      JSON.stringify(hashedAttributes),
      promoteAttributes
    );
    console.log(`Asset ${assetId} created successfully`);

    try {
      const assetResult = await contract.evaluateTransaction('ReadAsset', assetId);
      const asset = JSON.parse(assetResult.toString());
      console.log('Created asset:', asset);
      console.log('Asset policySet:', asset.policySet);
      console.log('Asset promoteAttributes:', asset.promoteAttributes);
    } catch (error) {
      console.error(`Error reading created asset ${assetId}:`, error.message);
    }

    const testData = { userId, assetId, owner: USERNAME };
    console.log(`Test data created: ${JSON.stringify(testData)}`);
    return testData;
  } catch (error) {
    console.error('Error in setupTestData:', error.message, error.responses || '');
    throw error;
  }
}

async function cleanupTestData(contract, assetId, userId) {
  try {
    if (assetId && contract) {
      let existsResult;
      try {
        existsResult = await contract.evaluateTransaction('AssetExists', assetId);
      } catch (error) {
        console.error(`Error checking if asset ${assetId} exists during cleanup:`, error.message);
        return;
      }
      if (existsResult && JSON.parse(existsResult.toString())) {
        await contract.submitTransaction('DeleteAsset', assetId);
        console.log(`Successfully deleted asset ${assetId}`);
      }
    }
    if (userId && contract) {
      let existsResult;
      try {
        existsResult = await contract.evaluateTransaction('UserExists', userId);
      } catch (error) {
        console.error(`Error checking if user ${userId} exists during cleanup:`, error.message);
        return;
      }
      if (existsResult && JSON.parse(existsResult.toString())) {
        await contract.submitTransaction('DeleteUser', userId);
        console.log(`Successfully deleted user ${userId}`);
      }
    }
  } catch (e) {
    console.error(`Cleanup failed for asset ${assetId} or user ${userId}:`, e.message);
  }
}

async function cleanupAssetsBatch(contract, assetIds) {
  const batchSize = 5;
  for (let i = 0; i < assetIds.length; i += batchSize) {
    const batch = assetIds.slice(i, i + batchSize);
    const promises = batch.map((assetId) => cleanupTestData(contract, assetId, null));
    await Promise.all(promises);
    console.log(`Completed cleanup batch ${i / batchSize + 1}/${Math.ceil(assetIds.length / batchSize)}`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

function hybridEncrypt(fragment, publicKey) {
  const plaintext = typeof fragment === 'string'
    ? Buffer.from(fragment, 'utf8')
    : Buffer.from(JSON.stringify(fragment), 'utf8');

  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const wrappedKey = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey
  );

  return {
    encryptedData: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    wrappedKey: wrappedKey.toString('base64'),
  };
}

async function measureFunction(contract, functionName, args, isQuery) {
  const startTime = performance.now();
  try {
    if (args.some(arg => arg === null || arg === undefined)) {
      console.error(`Invalid arguments for ${functionName}: ${JSON.stringify(args)}`);
      return { duration: -1, result: null };
    }

    if (functionName === 'CreateUser') {
      let existsResult;
      try {
        existsResult = await contract.evaluateTransaction('UserExists', args[0]);
      } catch (error) {
        console.error(`Error checking if user ${args[0]} exists:`, error.message);
        return { duration: -1, result: null };
      }
      if (existsResult && JSON.parse(existsResult.toString())) {
        console.log(`User ${args[0]} already exists, skipping creation`);
        return { duration: -1, result: null };
      }
    } else if (functionName === 'CreateAsset' || functionName === 'UpdateAsset') {
      let existsResult;
      try {
        existsResult = await contract.evaluateTransaction('AssetExists', args[0]);
      } catch (error) {
        console.error(`Error checking if asset ${args[0]} exists:`, error.message);
        return { duration: -1, result: null };
      }
      if (functionName === 'CreateAsset' && existsResult && JSON.parse(existsResult.toString())) {
        console.log(`Asset ${args[0]} already exists, skipping creation`);
        return { duration: -1, result: null };
      }
      if (functionName === 'UpdateAsset' && (!existsResult || !JSON.parse(existsResult.toString()))) {
        console.log(`Asset ${args[0]} does not exist, skipping update`);
        return { duration: -1, result: null };
      }

      const key = generateRandomAccessKey();
      const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
      const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

      const worker1Path = path.resolve(__dirname, './workers/w1-keys.json');
      const worker2Path = path.resolve(__dirname, './workers/w2-keys.json');
      let w1Keys, w2Keys;
      try {
        const w1Data = await fs.readFile(worker1Path, 'utf8');
        const w2Data = await fs.readFile(worker2Path, 'utf8');
        w1Keys = JSON.parse(w1Data);
        w2Keys = JSON.parse(w2Data);
      } catch (error) {
        console.error(`Error reading worker key files: ${error.message}`);
        throw error;
      }

      const encryptedFragments = {};
      for (const [idx, fragment] of Object.entries(fragmentsMap)) {
        encryptedFragments[idx] = {
          byKey1: hybridEncrypt(fragment, w1Keys.publicKey),
          byKey2: hybridEncrypt(fragment, w2Keys.publicKey),
        };
      }

      args[10] = hashAccessKey;
      args[11] = JSON.stringify(encryptedFragments);
      args[12] = JSON.stringify(hashedAttributes);
      args[13] = args[13] || JSON.stringify([
        {
          interest: ['department:engineering', 'role:developer'],
          languages: ['skills:python']
        }
      ]);
    } else if (functionName === 'PromoteAccess') {
      let asset;
      try {
        const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
        asset = assetResult ? JSON.parse(assetResult.toString()) : null;
      } catch (error) {
        console.error(`Error reading asset ${args[1]}:`, error.message);
        return { duration: -1, result: null };
      }
      if (!asset) {
        console.log(`Asset ${args[1]} not found, skipping PromoteAccess`);
        return { duration: -1, result: null };
      }
      let promotedAccess = [];
      if (asset.promotedAccess) {
        if (Array.isArray(asset.promotedAccess)) {
          promotedAccess = asset.promotedAccess;
        } else if (typeof asset.promotedAccess === 'string' && asset.promotedAccess) {
          try {
            promotedAccess = JSON.parse(asset.promotedAccess);
          } catch (e) {
            console.log(`Asset ${args[1]} has invalid promotedAccess string: ${e.message}, assuming empty`);
            promotedAccess = [];
          }
        }
      }
      if (promotedAccess.some(access => access.username === args[0])) {
        console.log(`User ${args[0]} already promoted for asset ${args[1]}, skipping`);
        return { duration: -1, result: null };
      }
    } else if (functionName === 'DemoteAccess') {
      let asset;
      try {
        const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
        asset = assetResult ? JSON.parse(assetResult.toString()) : null;
      } catch (error) {
        console.error(`Error reading asset ${args[1]}:`, error.message);
        return { duration: -1, result: null };
      }
      if (!asset) {
        console.log(`Asset ${args[1]} not found, skipping DemoteAccess`);
        return { duration: -1, result: null };
      }
      let promotedAccess = [];
      if (asset.promotedAccess) {
        if (Array.isArray(asset.promotedAccess)) {
          promotedAccess = asset.promotedAccess;
        } else if (typeof asset.promotedAccess === 'string' && asset.promotedAccess) {
          try {
            promotedAccess = JSON.parse(asset.promotedAccess);
          } catch (e) {
            console.log(`Asset ${args[1]} has invalid promotedAccess string: ${e.message}, assuming empty`);
            promotedAccess = [];
          }
        }
      }
      if (!promotedAccess.some(access => access.username === args[0])) {
        console.log(`User ${args[0]} not promoted for asset ${args[1]}, skipping`);
        return { duration: -1, result: null };
      }
    } else if (functionName === 'CheckAccess') {
      try {
        const assetResult = await contract.evaluateTransaction('ReadAsset', args[1]);
        const userResult = await contract.evaluateTransaction('GetUser', args[0]);
        const asset = assetResult ? JSON.parse(assetResult.toString()) : null;
        const user = userResult ? JSON.parse(userResult.toString()) : null;
        console.log(`CheckAccess - Asset state:`, asset);
        console.log(`CheckAccess - User state:`, user);
        if (!asset || !user) {
          console.log(`Asset ${args[1]} or user ${args[0]} not found, skipping CheckAccess`);
          return { duration: -1, result: null };
        }
      } catch (error) {
        console.error(`Error validating asset ${args[1]} or user ${args[0]} for CheckAccess:`, error.message);
        return { duration: -1, result: null };
      }
    }

    let result;
    if (isQuery) {
      result = await contract.evaluateTransaction(functionName, ...args);
    } else {
      result = await contract.submitTransaction(functionName, ...args);
    }
    const endTime = performance.now();
    return { duration: endTime - startTime, result };
  } catch (error) {
    console.error(`Error measuring ${functionName} with args ${JSON.stringify(args)}:`, error.message, error.responses || '');
    return { duration: -1, result: null };
  }
}

async function benchmarkApiCallTimes() {
  const results = [];
  let gateway;
  try {
    gateway = await connectToUserGateway(USERNAME, 'owner');
    const network = await gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);

    const testData = await setupTestData(contract);
    const { userId, assetId, owner } = testData || {};
    const runs = 5;

    const policyAttributes = [
      {
        interest: ['department:engineering', 'role:developer'],
        languages: ['skills:python']
      }
    ];
    const newUserId = generateUniqueId('user');
    const newAssetId = generateUniqueId('asset');
    const currentDate = new Date().toISOString();
    const key = generateRandomAccessKey();
    const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
    const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

    const functions = [
      { name: 'UserExists', args: [userId], isQuery: true },
      { name: 'GetUser', args: [userId], isQuery: true },
      { name: 'GetAssetsByOwnerAndName', args: [owner, 'TestAsset', 'DEMO'], isQuery: true },
      { name: 'AssetExists', args: [assetId], isQuery: true },
      { name: 'ReadAsset', args: [assetId], isQuery: true },
      { name: 'CheckAccess', args: [userId, assetId], isQuery: true },
      { name: 'GetAllAssets', args: [], isQuery: true },
      {
        name: 'CreateUser',
        args: [
          newUserId,
          'testRole',
          currentDate,
          'dummy-public-key',
          JSON.stringify(policyAttributes),
        ],
        isQuery: false,
      },
      {
        name: 'CreateAsset',
        args: [
          newAssetId,
          JSON.stringify({ description: 'Test asset' }),
          JSON.stringify(policyAttributes),
          'dummy-public-key',
          currentDate,
          currentDate,
          owner,
          'test-asset',
          'dummy-cid',
          '',
          hashAccessKey,
          JSON.stringify(fragmentsMap),
          JSON.stringify(hashedAttributes),
          JSON.stringify([
            {
              interest: ['department:engineering', 'role:developer'],
              languages: ['skills:python']
            }
          ]),
        ],
        isQuery: false,
      },
      {
        name: 'UpdateAsset',
        args: [
          assetId,
          JSON.stringify({ description: 'Updated asset' }),
          JSON.stringify(policyAttributes),
          'dummy-public-key',
          currentDate,
          currentDate,
          owner,
          'TestAsset',
          'dummy-cid',
          '',
          hashAccessKey,
          JSON.stringify(fragmentsMap),
          JSON.stringify(hashedAttributes),
          JSON.stringify([
            {
              interest: ['department:engineering', 'role:developer'],
              languages: ['skills:python']
            }
          ]),
        ],
        isQuery: false,
      },
      { name: 'RevokePermanentAccess', args: [userId, assetId, currentDate], isQuery: false },
      { name: 'GrantAccess', args: [userId, assetId, currentDate], isQuery: false },
    ];

    for (const func of functions) {
      let totalTime = 0;
      let successfulRuns = 0;

      console.log(`Benchmarking ${func.name}...`);
      if (func.isQuery) {
        const promises = Array.from({ length: runs }, () =>
          measureFunction(contract, func.name, func.args, func.isQuery)
        );
        const outcomes = await Promise.all(promises);
        for (const outcome of outcomes) {
          if (outcome.duration >= 0) {
            totalTime += outcome.duration;
            successfulRuns++;
          }
        }
      } else {
        for (let i = 0; i < runs; i++) {
          const outcome = await measureFunction(contract, func.name, func.args, func.isQuery);
          if (outcome.duration >= 0) {
            totalTime += outcome.duration;
            successfulRuns++;
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }

      const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
      results.push({
        function: func.name,
        avgLatency,
        latencyUnit: 'milliseconds',
        successfulRuns,
        totalRuns: runs
      });
    }

    await cleanupTestData(contract, assetId, newUserId);
    await fs.writeFile(
      path.join(__dirname, 'api_call_times_benchmark.json'),
      JSON.stringify(results, null, 2)
    );
    return results;
  } catch (error) {
    console.error('Error in benchmarkApiCallTimes:', error.message, error.responses || '');
    throw error;
  } finally {
    if (gateway) await gateway.disconnect();
  }
}

async function benchmarkCreateAsset() {
  const runs = 50;
  const batchSize = 5;
  const results = [];
  let gateway;
  const assetIds = [];

  try {
    gateway = await connectToUserGateway(USERNAME, 'owner');
    const network = await gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);

    let totalTime = 0;
    let successfulRuns = 0;

    for (let batch = 0; batch < runs; batch += batchSize) {
      const promises = [];
      for (let i = batch; i < Math.min(batch + batchSize, runs); i++) {
        promises.push(
          (async () => {
            const assetId = generateUniqueId('asset');
            assetIds.push(assetId);
            const metaData = JSON.stringify({ description: 'Test asset' });
            const policyAttributes = [
              {
                interest: ['department:engineering', 'role:developer'],
                languages: ['skills:python']
              }
            ];
            const policySet = JSON.stringify(policyAttributes);
            const publicKeyOwner = 'dummy-public-key';
            const now = new Date().toISOString();
            const owner = USERNAME;
            const name = 'test-asset';
            const cid = 'dummy-cid';
            const prevCid = '';
            const key = generateRandomAccessKey();
            const hashAccessKey = crypto.createHash('sha256').update(key).digest('hex');
            const { fragmentsMap, hashedAttributes } = generateShamirFragments(key, 2, 2);

            const args = [
              assetId,
              metaData,
              policySet,
              publicKeyOwner,
              now,
              now,
              owner,
              name,
              cid,
              prevCid,
              hashAccessKey,
              JSON.stringify(fragmentsMap),
              JSON.stringify(hashedAttributes),
              JSON.stringify([
                {
                  interest: ['department:engineering', 'role:developer'],
                  languages: ['skills:python']
                }
              ]),
            ];

            const outcome = await measureFunction(contract, 'CreateAsset', args, false);

            return outcome.duration;
          })()
        );
      }

      const batchResults = await Promise.all(promises);
      for (const duration of batchResults) {
        if (duration >= 0) {
          totalTime += duration;
          successfulRuns++;
        }
      }
      console.log(`Completed batch ${batch / batchSize + 1}/${Math.ceil(runs / batchSize)}`);
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    console.log('Cleaning up assets...');
    await cleanupAssetsBatch(contract, assetIds);

    const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;

    const output = {
      runs,
      avgLatency,
      latencyUnit: 'milliseconds',
      successfulRuns,
      totalRuns: runs
    };

    await fs.writeFile(
      path.join(__dirname, 'create_asset_benchmark.json'),
      JSON.stringify(output, null, 2)
    );

    return output;
  } catch (error) {
    console.error('Error in benchmarkCreateAsset:', error.message, error.responses || '');
    throw error;
  } finally {
    if (gateway) await gateway.disconnect();
  }
}

async function benchmarkQueryLatency() {
  const concurrencyLevels = [5, 80, 200, 400, 600, 1000];
  const results = [];
  let gateway;
  try {
    gateway = await connectToUserGateway(USERNAME, 'owner');
    const network = await gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);

    const testData = await setupTestData(contract);
    const { userId, assetId, owner } = testData || {};

    for (const concurrency of concurrencyLevels) {
      const readPromises = Array.from({ length: concurrency }, () =>
        measureFunction(contract, 'ReadAsset', [assetId], true)
      );
      const readStart = performance.now();
      const readOutcomes = await Promise.all(readPromises);
      const readTotalTime = (performance.now() - readStart) / 1000;
      const validReadDurations = readOutcomes.filter((o) => o.duration >= 0).map(o => o.duration);
      const readAvgLatency =
        validReadDurations.length > 0
          ? validReadDurations.reduce((sum, latency) => sum + latency, 0) / validReadDurations.length
          : -1;
      const readTPS = validReadDurations.length / readTotalTime;

      const assetsPromises = Array.from({ length: concurrency }, () =>
        measureFunction(contract, 'GetAssetsByOwnerAndName', [owner, 'TestAsset', 'DEMO'], true)
      );
      const assetsStart = performance.now();
      const assetsOutcomes = await Promise.all(assetsPromises);
      const assetsTotalTime = (performance.now() - assetsStart) / 1000;
      const validAssetsDurations = assetsOutcomes.filter((o) => o.duration >= 0).map(o => o.duration);
      const assetsAvgLatency =
        validAssetsDurations.length > 0
          ? validAssetsDurations.reduce((sum, latency) => sum + latency, 0) / validAssetsDurations.length
          : -1;
      const assetsTPS = validAssetsDurations.length / assetsTotalTime;

      results.push({
        concurrency,
        readAssetAvgLatency: readAvgLatency.toFixed(3),
        readAssetTPS: readTPS.toFixed(2),
        getAssetsByOwnerAndNameAvgLatency: assetsAvgLatency.toFixed(3),
        getAssetsByOwnerAndNameTPS: assetsTPS.toFixed(2)
      });
    }

    await fs.writeFile(
      path.join(__dirname, 'query_latency_benchmark.json'),
      JSON.stringify(results, null, 2)
    );

    await cleanupTestData(contract, assetId, null);
    return results;
  } catch (error) {
    console.error('Error in benchmarkQueryLatency:', error.message, error.responses || '');
    throw error;
  } finally {
    if (gateway) await gateway.disconnect();
  }
}

async function benchmarkPromoteDemote() {
  const results = [];
  let gateway = null;
  let contract = null;
  let testData = null;

  try {
    console.log('Connecting to gateway...');
    gateway = await connectToUserGateway(USERNAME, 'owner');
    const network = await gateway.getNetwork(CHANNEL_NAME);
    contract = network.getContract(CHAINCODE_NAME);

    console.log('Setting up test data...');
    testData = await setupTestData(contract);
    const { userId, assetId } = testData;
    const currentDate = new Date().toISOString();

    const functions = [
      {
        name: 'CheckAccess',
        args: [userId, assetId],
        isQuery: true,
        description: 'Check if user can get access'
      },
      {
        name: 'PromoteAccess',
        args: [userId, assetId, currentDate],
        isQuery: false,
        description: 'Promote user access'
      },
      {
        name: 'DemoteAccess',
        args: [userId, assetId, currentDate],
        isQuery: false,
        description: 'Demote user access'
      }
    ];

    for (const func of functions) {
      let totalTime = 0;
      let successfulRuns = 0;
      const totalRuns = 5;

      console.log(`Benchmarking ${func.name}...`);

      if (func.name === 'DemoteAccess') {
        try {
          await contract.submitTransaction('PromoteAccess', userId, assetId, currentDate);
          console.log(`Pre-promoted user ${userId} for DemoteAccess testing`);
        } catch (error) {
          console.error(`Error pre-promoting user ${userId} for DemoteAccess:`, error.message);
          results.push({
            function: func.name,
            description: func.description,
            avgLatency: -1,
            latencyUnit: 'milliseconds',
            successfulRuns: 0,
            totalRuns
          });
          continue;
        }
      }

      for (let i = 0; i < totalRuns; i++) {
        const outcome = await measureFunction(contract, func.name, func.args, func.isQuery);
        if (outcome.duration >= 0) {
          totalTime += outcome.duration;
          successfulRuns++;
        }
        if (func.name === 'PromoteAccess' && outcome.duration >= 0) {
          try {
            await contract.submitTransaction('DemoteAccess', userId, assetId, currentDate);
            console.log(`Demoted user ${userId} after PromoteAccess`);
          } catch (error) {
            console.error(`Error demoting user ${userId} after PromoteAccess:`, error.message);
          }
        } else if (func.name === 'DemoteAccess' && outcome.duration >= 0) {
          try {
            await contract.submitTransaction('PromoteAccess', userId, assetId, currentDate);
            console.log(`Re-promoted user ${userId} for next DemoteAccess`);
          } catch (error) {
            console.error(`Error re-promoting user ${userId} for DemoteAccess:`, error.message);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
      
      results.push({
        function: func.name,
        description: func.description,
        avgLatency,
        latencyUnit: 'milliseconds',
        successfulRuns,
        totalRuns
      });
    }

    console.log('Writing results to file...');
    await fs.writeFile(
      path.join(__dirname, 'promote_demote_benchmark.json'),
      JSON.stringify(results, null, 2)
    );

    return results;
  } catch (error) {
    console.error('Error in benchmarkPromoteDemote:', error.message, error.responses || '');
    throw error;
  } finally {
    if (testData && contract) {
      console.log('Cleaning up test data...');
      await cleanupTestData(contract, testData.assetId, testData.userId);
    }
    if (gateway) {
      console.log('Disconnecting gateway...');
      await gateway.disconnect();
    }
  }
}

async function benchmarkPromotionCheckByAttributeCount() {
  const attributeCounts = [1, 10, 50, 100, 500, 1000];
  const runsPerCount = 5;
  const results = [];
  let gateway = null;
  let contract = null;
  let testData = null;
  const userIds = [];

  try {
    console.log('Connecting to gateway for promotion check benchmark...');
    gateway = await connectToUserGateway(USERNAME, 'owner');
    const network = await gateway.getNetwork(CHANNEL_NAME);
    contract = network.getContract(CHAINCODE_NAME);

    console.log('Setting up test data for promotion check benchmark...');
    testData = await setupTestData(contract);
    const { assetId } = testData;

    for (const attributeCount of attributeCounts) {
      console.log(`Benchmarking CheckAccess with ${attributeCount} user attributes...`);

      let totalTime = 0;
      let successfulRuns = 0;
      let accessGrantedCount = 0;

      for (let run = 0; run < runsPerCount; run++) {
        // Randomly decide if this user should have the required attributes (~50% chance)
        const includeRequired = Math.random() < 0.5;
        const userId = generateUniqueId('user');
        userIds.push(userId);
        const policySet = generateUserPolicySet(attributeCount, includeRequired);
        const currentDate = new Date().toISOString();

        try {
          await contract.submitTransaction(
            'CreateUser',
            userId,
            'requester',
            currentDate,
            'dummy-public-key',
            policySet
          );
          console.log(`Created user ${userId} with ${attributeCount} attributes, required=${includeRequired}`);
          try {
            const userResult = await contract.evaluateTransaction('GetUser', userId);
            const user = JSON.parse(userResult.toString());
            console.log(`Created user PolicySet:`, user.PolicySet);
          } catch (error) {
            console.error(`Error reading created user ${userId}:`, error.message);
          }
        } catch (error) {
          console.error(`Error creating user ${userId} with ${attributeCount} attributes:`, error.message);
          continue;
        }

        const outcome = await measureFunction(contract, 'CheckAccess', [userId, assetId], true);
        if (outcome.duration >= 0) {
          totalTime += outcome.duration;
          successfulRuns++;
          try {
            const result = JSON.parse(outcome.result.toString());
            if (result.access) {
              accessGrantedCount++;
              console.log(`CheckAccess for user ${userId}: Access granted`);
            } else {
              console.log(`CheckAccess for user ${userId}: Access denied`);
            }
          } catch (error) {
            console.error(`Error parsing CheckAccess result for user ${userId}:`, error.message);
          }
        }
      }

      const avgLatency = successfulRuns > 0 ? (totalTime / successfulRuns).toFixed(3) : -1;
      const accessGrantedRate = successfulRuns > 0 ? (accessGrantedCount / successfulRuns).toFixed(3) : 0;
      results.push({
        attributeCount,
        avgLatency,
        latencyUnit: 'milliseconds',
        successfulRuns,
        totalRuns: runsPerCount,
        accessGrantedCount,
        accessGrantedRate
      });

      console.log(`Completed ${attributeCount} attributes: avgLatency=${avgLatency}ms, successfulRuns=${successfulRuns}/${runsPerCount}, accessGrantedRate=${accessGrantedRate}`);
    }

    console.log('Writing promotion check benchmark results to file...');
    await fs.writeFile(
      path.join(__dirname, 'promotion_check_by_attributes_benchmark.json'),
      JSON.stringify(results, null, 2)
    );

    return results;
  } catch (error) {
    console.error('Error in benchmarkPromotionCheckByAttributeCount:', error.message, error.responses || '');
    throw error;
  } finally {
    if (testData && contract) {
      console.log('Cleaning up test data for promotion check benchmark...');
      await cleanupTestData(contract, testData.assetId, null);
      for (const userId of userIds) {
        await cleanupTestData(contract, null, userId);
      }
    }
    if (gateway) {
      console.log('Disconnecting gateway for promotion check benchmark...');
      await gateway.disconnect();
    }
  }
}

async function runAllBenchmarks() {
  console.log('Starting benchmarks...');

  try {
    // console.log('Running API call times benchmark...');
    // const apiCallResults = await benchmarkApiCallTimes();
    // console.log('API Call Times Results:', JSON.stringify(apiCallResults, null, 2));

    // console.log('Running create asset benchmark...');
    // const createAssetResults = await benchmarkCreateAsset();
    // console.log('Create Asset Results:', JSON.stringify(createAssetResults, null, 2));

    // console.log('Running query latency benchmark...');
    // const queryLatencyResults = await benchmarkQueryLatency();
    // console.log('Query Latency Results:', JSON.stringify(queryLatencyResults, null, 2));

    console.log('Running promote/demote benchmark...');
    const promoteDemoteResults = await benchmarkPromoteDemote();
    console.log('Promote/Demote Results:', JSON.stringify(promoteDemoteResults, null, 2));

    console.log('Running promotion check by attribute count benchmark...');
    const promotionCheckResults = await benchmarkPromotionCheckByAttributeCount();
    console.log('Promotion Check by Attribute Count Results:', JSON.stringify(promotionCheckResults, null, 2));

    return {
      // apiCallTimes: apiCallResults,
      // createAsset: createAssetResults,
      // queryLatency: queryLatencyResults,
      promoteDemote: promoteDemoteResults,
      promotionCheckByAttributeCount: promotionCheckResults
    };
  } catch (error) {
    console.error('Error running benchmarks:', error.stack);
    throw error;
  }
}

runAllBenchmarks()
  .then((results) => {
    console.log('Benchmarks completed successfully.');
    console.log('Results:', JSON.stringify(results, null, 2));
  })
  .catch((error) => {
    console.error('Benchmarking failed:', error.stack);
    process.exit(1);
  });
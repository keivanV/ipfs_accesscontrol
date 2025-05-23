'use strict';

const stringify = require('json-stringify-deterministic');
const sortKeysRecursive = require('sort-keys-recursive');
const { Contract } = require('fabric-contract-api');
const { TextDecoder } = require('node:util');
const crypto = require('crypto');

const { split, join } = require('shamir');

class AssetTransferABAC extends Contract {
    async CreateUser(ctx, username, role, createdAt, publicKey, policySet) {
        const exists = await this.UserExists(ctx, username);
        if (exists) {
            throw new Error(`User ${username} already exists`);
        }
    
        const user = {
            Username: username,
            Role: role,
            CreatedAt: createdAt,
            PublicKey: publicKey,
            PolicySet: JSON.parse(policySet)
        };
    
        await ctx.stub.putState(username, Buffer.from(stringify(sortKeysRecursive(user))));
        return JSON.stringify(user);
    }

    async hashKeyValuePairs(policyAttributes) {
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

    async UserExists(ctx, username) {
        const userJSON = await ctx.stub.getState(username);
        return userJSON && userJSON.length > 0;
    }

    async GetUser(ctx, username) {
        const userJSON = await ctx.stub.getState(username);
        if (!userJSON || userJSON.length === 0) {
            throw new Error(`User ${username} does not exist`);
        }
        return userJSON.toString();
    }

    async GetAssetsByOwnerAndName(ctx, owner, name, type) {
        const startKey = '';
        const endKey = '';
        const matchedAssets = [];
    
        try {
            for await (const { key, value } of ctx.stub.getStateByRange(startKey, endKey)) {
                const strValue = value.toString('utf8');
                let record;
                try {
                    record = JSON.parse(strValue); 
                } catch (err) {
                    console.log("Error parsing JSON", err);
                    continue; 
                }
    
                if (record.owner === owner && record.name === name && record.type == type) {
                    matchedAssets.push({ Key: key, Record: record });
                }
            }
        } catch (error) {
            console.error("Error iterating through assets", error);
            throw new Error(`Failed to get assets: ${error.message}`);
        }
    
        console.info("Matched Assets:", matchedAssets);
        return JSON.stringify(matchedAssets);
    }

    async AssetExists(ctx, id) {
        const assetJSON = await ctx.stub.getState(id);
        return assetJSON && assetJSON.length > 0;
    }

    async CreateAsset(ctx, id, metaData, policySet, publicKeyOwner, releaseAt, updatedAt, owner, name, cid, PrevCid, hashAccessKey, fragmentsMap, hashedAttributes, promoteAttributes) {
        const exists = await this.AssetExists(ctx, id);
        
        if (exists) {
            throw new Error(`The asset ${id} already exists`);
        }

        const asset = {
            type: "DEMO",
            ID: id,
            MetaData: metaData,
            policySet: JSON.parse(policySet),
            publicKeyOwner: publicKeyOwner,
            ReleasedAt: releaseAt,
            UpdatedAt: updatedAt,
            Requesters: [],
            revokedAccess: [],
            promotedAccess: [],
            owner: owner,
            name: name,
            cid: cid,
            PrevCid: PrevCid,
            hashAccessKey: hashAccessKey,
            fragmentsMap: JSON.parse(fragmentsMap),
            hashedAttributes: JSON.parse(hashedAttributes),
            promoteAttributes: JSON.parse(promoteAttributes)
        };

        await ctx.stub.putState(id, Buffer.from(stringify(sortKeysRecursive(asset))));
        return JSON.stringify(asset);
    }

    async ReadAsset(ctx, id) {
        const assetJSON = await ctx.stub.getState(id);
        if (!assetJSON || assetJSON.length === 0) {
            throw new Error(`The asset ${id} does not exist`);
        }
        return assetJSON.toString();
    }
    async UpdateAsset(ctx, id, metaData, policySet, publicKeyOwner, releaseAt, updatedAt, owner, name, cid, PrevCid, hashAccessKey, fragmentsMap, hashedAttributes, promoteAttributes) {
        const exists = await this.AssetExists(ctx, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }
    
        const assetString = await this.ReadAsset(ctx, id);
        const existingAsset = JSON.parse(assetString);
    
        let parsedPromoteAttributes;
        try {
            parsedPromoteAttributes = typeof promoteAttributes === 'string' ? JSON.parse(promoteAttributes) : promoteAttributes;
            if (!Array.isArray(parsedPromoteAttributes)) {
                parsedPromoteAttributes = [parsedPromoteAttributes];
            }
            parsedPromoteAttributes = parsedPromoteAttributes.filter(attr => {
                const interests = Array.isArray(attr.interest) ? attr.interest : [];
                const languages = Array.isArray(attr.languages) ? attr.languages : [];
                return interests.length > 0 || languages.length > 0;
            });
            if (parsedPromoteAttributes.length === 0) {
                throw new Error("promoteAttributes must contain at least one valid policy");
            }
        } catch (error) {
            throw new Error(`Invalid promoteAttributes format: ${error.message}`);
        }
    
        let parsedPolicySet = policySet;
        let parsedFragmentsMap = fragmentsMap;
        let parsedHashedAttributes = hashedAttributes;
        try {
            parsedPolicySet = typeof policySet === 'string' ? JSON.parse(policySet) : policySet;
            parsedFragmentsMap = typeof fragmentsMap === 'string' ? JSON.parse(fragmentsMap) : fragmentsMap;
            parsedHashedAttributes = typeof hashedAttributes === 'string' ? JSON.parse(hashedAttributes) : hashedAttributes;
        } catch (error) {
            throw new Error(`Invalid JSON format in policySet, fragmentsMap, or hashedAttributes: ${error.message}`);
        }
    
        const updatedAsset = {
            type: "DEMO",
            ID: id,
            MetaData: metaData,
            policySet: parsedPolicySet,
            publicKeyOwner: publicKeyOwner,
            ReleasedAt: releaseAt,
            UpdatedAt: updatedAt,
            Requesters: existingAsset.Requesters || [],
            revokedAccess: existingAsset.revokedAccess || [],
            promotedAccess: existingAsset.promotedAccess || [],
            owner: owner,
            name: name,
            cid: cid,
            PrevCid: PrevCid,
            hashAccessKey: hashAccessKey,
            fragmentsMap: parsedFragmentsMap,
            hashedAttributes: parsedHashedAttributes,
            promoteAttributes: parsedPromoteAttributes
        };
    
        await ctx.stub.putState(id, Buffer.from(stringify(sortKeysRecursive(updatedAsset))));
    
        return JSON.stringify(updatedAsset);
    }
    
    async RevokePermanentAccess(ctx, username, assetID, revokedAt) {
        const assetString = await this.ReadAsset(ctx, assetID);
        if (!assetString) {
            throw new Error(`Asset with ID ${assetID} not found.`);
        }
        
        const asset = JSON.parse(assetString);
    
        if (!asset.revokedAccess) {
            asset.revokedAccess = [];
        }

        asset.revokedAccess.push({
            username: username,
            type: 'permanent',
            revokedAt: revokedAt
        });
    
        await ctx.stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
    
        return JSON.stringify(asset);
    }

    async RestoreAccess(ctx, username, assetID, restoredAt) {
        const assetString = await this.ReadAsset(ctx, assetID);
        if (!assetString) {
            throw new Error(`Asset with ID ${assetID} not found.`);
        }
        
        const asset = JSON.parse(assetString);
    
        if (!asset.revokedAccess || asset.revokedAccess.length === 0) {
            throw new Error(`No revoked access found for asset ${assetID}`);
        }

        const initialLength = asset.revokedAccess.length;
        asset.revokedAccess = asset.revokedAccess.filter(access => 
            !(access.username === username && access.type === 'permanent')
        );

        if (asset.revokedAccess.length === initialLength) {
            throw new Error(`User ${username} was not permanently revoked for asset ${assetID}`);
        }

        if (!asset.accessHistory) {
            asset.accessHistory = [];
        }
        asset.accessHistory.push({
            username: username,
            action: 'restored',
            restoredAt: restoredAt
        });
    
        await ctx.stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
    
        return JSON.stringify(asset);
    }

    async PromoteAccess(ctx, username, assetID, promotedAt) {
        const assetString = await this.ReadAsset(ctx, assetID);
        if (!assetString) {
            throw new Error(`Asset with ID ${assetID} not found.`);
        }
        
        const asset = JSON.parse(assetString);
    
        const userString = await this.GetUser(ctx, username);
        if (!userString) {
            throw new Error(`User ${username} not found.`);
        }
        const user = JSON.parse(userString);
    
        let userPolicySet;
        try {
            if (typeof user.PolicySet === 'string') {
                userPolicySet = JSON.parse(user.PolicySet);
            } else if (Array.isArray(user.PolicySet)) {
                userPolicySet = user.PolicySet;
            } else if (typeof user.PolicySet === 'object' && user.PolicySet !== null) {
                userPolicySet = [user.PolicySet];
            } else {
                throw new Error("PolicySet is neither a valid JSON string, object, nor an array");
            }
    
            if (!Array.isArray(userPolicySet)) {
                throw new Error("PolicySet should be an array");
            }
    
            userPolicySet = userPolicySet.filter(policy => {
                const interests = Array.isArray(policy.interest) ? policy.interest : [];
                const languages = Array.isArray(policy.languages) ? policy.languages : [];
                return interests.length > 0 || languages.length > 0;
            });
    
            if (userPolicySet.length === 0) {
                throw new Error(`User ${username} has no valid policy attributes`);
            }
        } catch (error) {
            throw new Error(`Invalid PolicySet format for user ${username}: ${error.message}`);
        }
    
        let promoteAttributes = asset.promoteAttributes || [];
        if (typeof promoteAttributes === 'string') {
            try {
                promoteAttributes = JSON.parse(promoteAttributes);
            } catch (error) {
                throw new Error(`Invalid promoteAttributes format for asset ${assetID}: ${error.message}`);
            }
        }
        if (!Array.isArray(promoteAttributes)) {
            promoteAttributes = [promoteAttributes];
        }
    
        promoteAttributes = promoteAttributes.filter(attr => {
            const interests = Array.isArray(attr.interest) ? attr.interest : [];
            const languages = Array.isArray(attr.languages) ? attr.languages : [];
            return interests.length > 0 || languages.length > 0;
        });
    
        console.log(`[PromoteAccess] promoteAttributes: ${JSON.stringify(promoteAttributes)}`);
        console.log(`[PromoteAccess] userPolicySet: ${JSON.stringify(userPolicySet)}`);
    
        if (promoteAttributes.length === 0) {
            throw new Error(`No valid promotion attributes defined for asset ${assetID}`);
        }
    
        const hasMatchingAttributes = promoteAttributes.every(attr => {
            const requiredInterests = Array.isArray(attr.interest) ? attr.interest : [];
            const requiredLanguages = Array.isArray(attr.languages) ? attr.languages : [];
    
            return userPolicySet.some(userPolicy => {
                const userInterests = Array.isArray(userPolicy.interest) ? userPolicy.interest : [];
                const userLanguages = Array.isArray(userPolicy.languages) ? userPolicy.languages : [];
    
                const interestMatch = requiredInterests.every(i => userInterests.includes(i));
                const languageMatch = requiredLanguages.every(l => userLanguages.includes(l));
    
                console.log(`[PromoteAccess] Checking attribute: promoteAttr=${JSON.stringify(attr)}, userPolicy=${JSON.stringify(userPolicy)}, interestMatch=${interestMatch}, languageMatch=${languageMatch}`);
                
                return interestMatch && languageMatch;
            });
        });
    
        if (!hasMatchingAttributes) {
            throw new Error(`User ${username} does not meet promotion requirements for asset ${assetID}`);
        }
    
        if (!Array.isArray(asset.promotedAccess)) {
            asset.promotedAccess = [];
        }
    
        const alreadyPromoted = asset.promotedAccess.some(access => access.username === username);
        if (alreadyPromoted) {
            throw new Error(`User ${username} already has promoted access for asset ${assetID}`);
        }
    
        asset.promotedAccess.push({
            username: username,
            promotedAt: promotedAt
        });
    
        await ctx.stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
    
        return JSON.stringify(asset);
    }
    

    async DemoteAccess(ctx, username, assetID, demotedAt) {
        const assetString = await this.ReadAsset(ctx, assetID);
        if (!assetString) {
            throw new Error(`Asset with ID ${assetID} not found.`);
        }
        
        const asset = JSON.parse(assetString);
    
        if (!asset.promotedAccess || asset.promotedAccess.length === 0) {
            throw new Error(`No promoted access found for asset ${assetID}`);
        }

        const initialLength = asset.promotedAccess.length;
        asset.promotedAccess = asset.promotedAccess.filter(access => access.username !== username);

        if (asset.promotedAccess.length === initialLength) {
            throw new Error(`User ${username} was not found in promoted access for asset ${assetID}`);
        }

        if (!asset.revokedAccess) {
            asset.revokedAccess = [];
        }
        // asset.revokedAccess.push({
        //     username: username,
        //     type: 'demotion',
        //     demotedAt: demotedAt
        // });
    
        await ctx.stub.putState(assetID, Buffer.from(stringify(sortKeysRecursive(asset))));
    
        return JSON.stringify(asset);
    }
    
    // async CheckAccess(ctx, username, assetID) {
    //     let user = await this.GetUser(ctx, username);
    //     user = JSON.parse(user);
    
    //     let userPolicySet;
    
    //     try {
    //         if (typeof user.PolicySet === 'string') {
    //             userPolicySet = JSON.parse(user.PolicySet);
    //         } else if (Array.isArray(user.PolicySet)) {
    //             userPolicySet = user.PolicySet;
    //         } else if (typeof user.PolicySet === 'object') {
    //             userPolicySet = [user.PolicySet];
    //         } else {
    //             throw new Error("PolicySet is neither a valid JSON string, object, nor an array");
    //         }
    
    //         if (!Array.isArray(userPolicySet)) {
    //             throw new Error("PolicySet should be an array");
    //         }
    //     } catch (error) {
    //         console.error(`Invalid PolicySet format for user ${username}:`, user.PolicySet);
    //         throw new Error(`Invalid JSON format for PolicySet of user ${username}: ${error.message}`);
    //     }
    
    //     const assetJSON = await ctx.stub.getState(assetID);
    //     if (!assetJSON || assetJSON.length === 0) {
    //         throw new Error(`Asset ${assetID} does not exist`);
    //     }
    //     const asset = JSON.parse(assetJSON.toString());
    
    //     if (typeof asset.policySet === 'string') {
    //         asset.policySet = JSON.parse(asset.policySet);
    //     }
    
    //     const isPermanentRevoked = asset.revokedAccess && asset.revokedAccess.some(access => 
    //         access.username === username && access.type === 'permanent'
    //     );
    //     if (isPermanentRevoked) {
    //         return { access: false };
    //     }
    
    //     const allAssets = await this.GetAllAssets(ctx);
    //     const parsedAssets = JSON.parse(allAssets);
    //     const isBlockedByOwner = parsedAssets.some(({ Record }) => {
    //         if (Record.owner === asset.owner && Record.revokedAccess) {
    //             return Record.revokedAccess.some(access => 
    //                 access.username === username && access.type === 'permanent'
    //             );
    //         }
    //         return false;
    //     });
    
    //     if (isBlockedByOwner) {
    //         return { access: false };
    //     }
    
    //     const userHasAccess = asset.policySet.every(assetPolicy => 
    //         userPolicySet.some(userPolicy => {
    //             const isInterestSubset = assetPolicy.interest.every(interest => 
    //                 userPolicy.interest.includes(interest)
    //             );
    
    //             const isLanguagesSubset = assetPolicy.languages.every(language => 
    //                 userPolicy.languages.includes(language)
    //             );
    
    //             return isInterestSubset && isLanguagesSubset;
    //         })
    //     );
        
    //     if (!userHasAccess) {
    //         return { access: false };
    //     }
    
    //     const extractedShares = {};
    //     asset.fragmentsMap.slice(0, asset.hashedAttributes.length).forEach((fragment, index) => {
    //         extractedShares[index + 1] = fragment.share;
    //     });

    //     const result = {};
    //     for (const key in extractedShares) {
    //         if (extractedShares.hasOwnProperty(key)) {
    //             const numbers = Object.values(extractedShares[key]);
    //             result[key] = new Uint8Array(numbers);
    //         }
    //     }

    //     const recovered = join(result);
    //     const utf8Decoder = new TextDecoder();
    //     const recoveredAccessKey = utf8Decoder.decode(recovered);
    
    //     return { access: true, owner: asset.owner, key: recoveredAccessKey };
    // }


async CheckAccess(ctx, username, assetID) {
    // Retrieve user
    let user = await this.GetUser(ctx, username);
    user = JSON.parse(user);
    let userPolicySet;

    try {
        if (typeof user.PolicySet === 'string') {
            userPolicySet = JSON.parse(user.PolicySet);
        } else if (Array.isArray(user.PolicySet)) {
            userPolicySet = user.PolicySet;
        } else if (typeof user.PolicySet === 'object') {
            userPolicySet = [user.PolicySet];
        } else {
            throw new Error("PolicySet is neither a valid JSON string, object, nor an array");
        }
        if (!Array.isArray(userPolicySet)) {
            throw new Error("PolicySet should be an array");
        }
    } catch (error) {
        console.error(`Invalid PolicySet format for user ${username}:`, user.PolicySet);
        throw new Error(`Invalid JSON format for PolicySet of user ${username}: ${error.message}`);
    }

    // Retrieve asset
    const assetJSON = await ctx.stub.getState(assetID);
    if (!assetJSON || assetJSON.length === 0) {
        throw new Error(`Asset ${assetID} does not exist`);
    }
    const asset = JSON.parse(assetJSON.toString());
    if (typeof asset.policySet === 'string') {
        asset.policySet = JSON.parse(asset.policySet);
    }

    // Check for permanent revocation
    const isPermanentRevoked = asset.revokedAccess && asset.revokedAccess.some(access => 
        access.username === username && access.type === 'permanent'
    );
    if (isPermanentRevoked) {
        return JSON.stringify({ access: false });
    }

    // Check owner-level revocations
    const allAssets = await this.GetAllAssets(ctx);
    const parsedAssets = JSON.parse(allAssets);
    const isBlockedByOwner = parsedAssets.some(({ Record }) => {
        if (Record.owner === asset.owner && Record.revokedAccess) {
            return Record.revokedAccess.some(access => 
                access.username === username && access.type === 'permanent'
            );
        }
        return false;
    });
    if (isBlockedByOwner) {
        return JSON.stringify({ access: false });
    }

    // Check policy matching dynamically
    const userHasAccess = asset.policySet.every(assetPolicy => 
        userPolicySet.some(userPolicy => {
            return Object.keys(assetPolicy).every(key => {
                // If userPolicy lacks the key or it's not an array, consider it a mismatch
                if (!userPolicy[key] || !Array.isArray(userPolicy[key])) {
                    return false;
                }
                // Check if all required values for this key are present in userPolicy
                return assetPolicy[key].every(value => userPolicy[key].includes(value));
            });
        })
    );

    if (!userHasAccess) {
        return JSON.stringify({ access: false });
    }

    // Extract shares and recover key
    const extractedShares = {};
    asset.fragmentsMap.slice(0, asset.hashedAttributes.length).forEach((fragment, index) => {
        extractedShares[index + 1] = fragment.share;
    });
    const result = {};
    for (const key in extractedShares) {
        if (extractedShares.hasOwnProperty(key)) {
            const numbers = Object.values(extractedShares[key]);
            result[key] = new Uint8Array(numbers);
        }
    }
    const recovered = join(result);
    const utf8Decoder = new TextDecoder();
    const recoveredAccessKey = utf8Decoder.decode(recovered);
    return JSON.stringify({ access: true, owner: asset.owner, key: recoveredAccessKey });
}

    async GrantAccess(ctx, username, assetID, grantedAt) {
        const assetString = await this.ReadAsset(ctx, assetID);
        const asset = JSON.parse(assetString);

        asset.Requesters.push({ username: username, grantedAt: grantedAt });
        await ctx.stub.putState(assetID, Buffer.from(JSON.stringify(asset)));

        return JSON.stringify(asset);
    }

    async DeleteAsset(ctx, id) {
        const exists = await this.AssetExists(ctx, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }

        await ctx.stub.deleteState(id);
    }

    async DeleteUser(ctx, username) {
        const exists = await this.UserExists(ctx, username);
        if (!exists) {
            throw new Error(`User ${username} does not exist`);
        }
        await ctx.stub.deleteState(username);
        return `User ${username} deleted successfully`;
    }


    
    async DeleteAssetPublic(ctx, id) {
        const exists = await this.AssetExists(ctx, id);
        if (!exists) {
            throw new Error(`The asset ${id} does not exist`);
        }
        await ctx.stub.deleteState(id);
    }

    async TransferAsset(ctx, id, newPublicKeyOwner) {
        const assetString = await this.ReadAsset(ctx, id);
        const asset = JSON.parse(assetString);
        const oldOwner = asset.publicKeyOwner;
        asset.publicKeyOwner = newPublicKeyOwner;
        asset.UpdatedAt = new Date().toISOString();

        await ctx.stub.putState(id, Buffer.from(stringify(sortKeysRecursive(asset))));
        return oldOwner;
    }

    async GetAllAssets(ctx) {
        const startKey = '';
        const endKey = '';
        const allResults = [];
    
        try {
            for await (const { key, value } of ctx.stub.getStateByRange(startKey, endKey)) {
                const strValue = value.toString('utf8');
                let record;
                try {
                    record = JSON.parse(strValue);
                } catch (err) {
                    console.log("Error parsing JSON", err);
                    record = strValue;
                }
                allResults.push({ Key: key, Record: record });
            }
        } catch (error) {
            console.error("Error iterating through state data", error);
            throw new Error(`Failed to get assets: ${error.message}`);
        }
    
        console.info(allResults);
        return JSON.stringify(allResults);
    }

    async GetAssetHistory(ctx, id) {
        const history = [];
        const iterator = await ctx.stub.getHistoryForKey(id);
        let result;
        while (true) {
            result = await iterator.next();
            if (result.done) {
                await iterator.close();
                break;
            }
            const tx = {
                txId: result.value.txId,
                timestamp: new Date(result.value.timestamp.getSeconds() * 1000).toISOString(),
                isDelete: result.value.isDelete,
                value: result.value.value.toString('utf8'),
            };
            try {
                tx.value = JSON.parse(tx.value);
            } catch (e) {
                console.log('Non-JSON value in history:', tx.value);
            }
            history.push(tx);
        }
        return JSON.stringify(history);
    }
}

module.exports = AssetTransferABAC;
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const xml2js = require('xml2js');
const fs = require('fs');
const path = require('path');

const app = express();

const parser = new xml2js.Parser({ explicitArray: false });

function readConfig() {
    const filePath = path.join(__dirname, '../q.xml');
    const xml = fs.readFileSync(filePath, 'utf8');
    let config;
    parser.parseString(xml, (err, result) => {
        if (err) throw err;
        config = result.config;
    });
    return config;
}

const config = readConfig();
const a = config.a;
const b = config.b;
const c = config.c;
async function getJwt() {
    try {
        const response = await axios.get(c, {
            params: {
                uid: a,
                password: b
            }
        });
        return response.data.Starexx[0].Token;
    } catch (error) {
        console.error("Error fetching JWT:", error);
        return null;
    }
}

function encryptID(x) {
    const dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff'];
    const xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f'];
    x = parseInt(x);
    x = x / 128;
    if (x > 128) {
        x = x / 128;
        if (x > 128) {
            x = x / 128;
            if (x > 128) {
                x = x / 128;
                const strx = parseInt(x);
                const y = (x - strx) * 128;
                const stry = parseInt(y);
                const z = (y - stry) * 128;
                const strz = parseInt(z);
                const n = (z - strz) * 128;
                const strn = parseInt(n);
                const m = (n - strn) * 128;
                return dec[parseInt(m)] + dec[parseInt(n)] + dec[parseInt(z)] + dec[parseInt(y)] + xxx[parseInt(x)];
            } else {
                const strx = parseInt(x);
                const y = (x - strx) * 128;
                const stry = parseInt(y);
                const z = (y - stry) * 128;
                const strz = parseInt(z);
                const n = (z - strz) * 128;
                const strn = parseInt(n);
                return dec[parseInt(n)] + dec[parseInt(z)] + dec[parseInt(y)] + xxx[parseInt(x)];
            }
        }
    }
}

function encryptApi(plainText) {
    const key = Buffer.from([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56]);
    const iv = Buffer.from([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37]);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function parseResults(parsedResults) {
    const resultDict = {};
    for (const result of parsedResults) {
        const fieldData = {};
        fieldData['wire_type'] = result.wire_type;
        if (result.wire_type === "varint") {
            fieldData['data'] = result.data;
            resultDict[result.field] = fieldData;
        } else if (result.wire_type === "string") {
            fieldData['data'] = result.data;
            resultDict[result.field] = fieldData;
        } else if (result.wire_type === 'length_delimited') {
            fieldData["data"] = parseResults(result.data.results);
            resultDict[result.field] = fieldData;
        }
    }
    return resultDict;
}

function getAvailableRoom(inputText) {
    const parsedResults = []; // Replace with actual protobuf parsing logic
    const parsedResultsDict = parseResults(parsedResults);
    return JSON.stringify(parsedResultsDict);
}

app.get('/', (req, res) => {
    res.json({
        "FF Information": [{
            "credits": "Starexx"
        }]
    });
});

app.get('/info', async (req, res) => {
    try {
        const playerId = req.query.uid;
        if (!playerId) {
            return res.status(400).json({
                "Error": [{
                    "message": "Player ID is required"
                }]
            });
        }

        const jwtToken = await getJwt();
        if (!jwtToken) {
            return res.status(500).json({
                "Error": [{
                    "message": "Failed to fetch JWT token"
                }]
            });
        }

        const data = encryptApi(`08${encryptID(playerId)}1007`);
        const url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow";
        const headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': `Bearer ${jwtToken}`,
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        };

        const response = await axios.post(url, data, {
            headers: headers,
            httpsAgent: new(require('https').Agent)({
                rejectUnauthorized: false
            })
        });

        if (response.status === 200) {
            const hexResponse = response.data.toString('hex');
            const jsonResult = getAvailableRoom(hexResponse);
            const parsedData = JSON.parse(jsonResult);

            const playerData = {
                "Player": {
                    "Name": parsedData["1"]["data"]["3"]["data"],
                    "UID": playerId,
                    "Likes": parsedData["1"]["data"]["21"]["data"],
                    "Level": parsedData["1"]["data"]["6"]["data"],
                    "Region": parsedData["1"]["data"]["5"]["data"],
                    "Bio": parsedData["9"]["data"]["9"]["data"],
                    "BooyahPassLavel": parsedData["1"]["data"]["18"]["data"],
                    "AccountCreated": new Date(parsedData["1"]["data"]["44"]["data"] * 1000).toISOString()
                }
            };

            res.json({
                "Starexx": [{
                    "Massage": "Player information retrieved successfully",
                    "Data": playerData
                }]
            });
        } else {
            res.status(response.status).json({
                "Error": [{
                    "message": `API request failed with status code: ${response.status}`
                }]
            });
        }
    } catch (error) {
        res.status(500).json({
            "Error": [{
                "message": `An unexpected error occurred: ${error.message}`
            }]
        });
    }
});

const PORT = 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

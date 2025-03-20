const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { Parser } = require('protobuf-decoder');
const { DateTime } = require('luxon');

const app = express();
app.use(express.json());

const com_garena_msdk_uid = "3197059560";
const com_garena_msdk_password = "3EC146CD4EEF7A640F2967B06D7F4413BD4FB37382E0ED260E214E8BACD96734";
const get_jwt = "https://ariflexlabs-jwt-gen.onrender.com/fetch-token";

const getJwt = async () => {
    try {
        const params = { uid: com_garena_msdk_uid, password: com_garena_msdk_password };
        const response = await axios.get(get_jwt, { params });
        if (response.status === 200) {
            return response.data["JWT TOKEN"];
        }
        return null;
    } catch (error) {
        console.error("Error fetching JWT:", error);
        return null;
    }
};

const encryptID = (x) => {
    x = parseInt(x);
    const dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff'];
    const xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f'];
    x = x / 128;
    if (x > 128) {
        x = x / 128;
        if (x > 128) {
            x = x / 128;
            if (x > 128) {
                x = x / 128;
                const strx = parseInt(x);
                const y = (x - strx) * 128;
                const stry = parseInt(y).toString();
                const z = (y - parseInt(stry)) * 128;
                const strz = parseInt(z).toString();
                const n = (z - parseInt(strz)) * 128;
                const strn = parseInt(n).toString();
                const m = (n - parseInt(strn)) * 128;
                return dec[parseInt(m)] + dec[parseInt(n)] + dec[parseInt(z)] + dec[parseInt(y)] + xxx[parseInt(x)];
            } else {
                const strx = parseInt(x);
                const y = (x - strx) * 128;
                const stry = parseInt(y).toString();
                const z = (y - parseInt(stry)) * 128;
                const strz = parseInt(z).toString();
                const n = (z - parseInt(strz)) * 128;
                const strn = parseInt(n).toString();
                return dec[parseInt(n)] + dec[parseInt(z)] + dec[parseInt(y)] + xxx[parseInt(x)];
            }
        }
    }
};

const encryptApi = (plainText) => {
    const key = Buffer.from([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56]);
    const iv = Buffer.from([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37]);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    let encrypted = cipher.update(Buffer.from(plainText, 'hex'));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('hex');
};

const parseResults = (parsedResults) => {
    const resultDict = {};
    for (const result of parsedResults) {
        const fieldData = { wire_type: result.wire_type };
        if (result.wire_type === "varint") {
            fieldData.data = result.data;
            resultDict[result.field] = fieldData;
        } else if (result.wire_type === "string") {
            fieldData.data = result.data;
            resultDict[result.field] = fieldData;
        } else if (result.wire_type === 'length_delimited') {
            fieldData.data = parseResults(result.data.results);
            resultDict[result.field] = fieldData;
        }
    }
    return resultDict;
};

const getAvailableRoom = (inputText) => {
    try {
        const parser = new Parser();
        const parsedResults = parser.parse(inputText);
        const parsedResultsDict = parseResults(parsedResults);
        return JSON.stringify(parsedResultsDict);
    } catch (error) {
        throw new Error(`Parser error: ${error.message}`);
    }
};

app.get('/', (req, res) => {
    res.json({
        "FF Information": [
            {
                "credits": "Starexx"
            }
        ]
    });
});

app.get('/info', async (req, res) => {
    try {
        const playerId = req.query.id;
        if (!playerId) {
            return res.status(400).json({
                "Error": [
                    {
                        "message": "Player ID is required"
                    }
                ]
            });
        }

        const jwtToken = await getJwt();
        if (!jwtToken) {
            return res.status(500).json({
                "Error": [
                    {
                        "message": "Failed to generate JWT token"
                    }
                ]
            });
        }

        const data = Buffer.from(encryptApi(`08${encryptID(playerId)}1007`), 'hex');
        const url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow";
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

        const response = await axios.post(url, data, { headers });

        if (response.status === 200) {
            const hexResponse = response.data.toString('hex');
            const jsonResult = getAvailableRoom(hexResponse);
            const parsedData = JSON.parse(jsonResult);

            const playerData = {
                basic_info: {
                    name: parsedData["1"]["data"]["3"]["data"],
                    id: playerId,
                    likes: parsedData["1"]["data"]["21"]["data"],
                    level: parsedData["1"]["data"]["6"]["data"],
                    server: parsedData["1"]["data"]["5"]["data"],
                    bio: parsedData["9"]["data"]["9"]["data"],
                    booyah_pass_level: parsedData["1"]["data"]["18"]["data"],
                    account_created: DateTime.fromSeconds(parsedData["1"]["data"]["44"]["data"]).toFormat("yyyy-MM-dd HH:mm:ss")
                }
            };

            try {
                playerData.animal = {
                    name: parsedData["8"]["data"]["2"]["data"]
                };
            } catch {
                playerData.animal = null;
            }

            try {
                playerData.clan = {
                    name: parsedData["6"]["data"]["2"]["data"],
                    id: parsedData["6"]["data"]["1"]["data"],
                    level: parsedData["6"]["data"]["4"]["data"],
                    members_count: parsedData["6"]["data"]["6"]["data"],
                    leader: {
                        id: parsedData["6"]["data"]["3"]["data"],
                        name: parsedData["7"]["data"]["3"]["data"],
                        level: parsedData["7"]["data"]["6"]["data"],
                        booyah_pass_level: parsedData["7"]["data"]["18"]["data"],
                        likes: parsedData["7"]["data"]["21"]["data"],
                        account_created: DateTime.fromSeconds(parsedData["7"]["data"]["44"]["data"]).toFormat("yyyy-MM-dd HH:mm:ss")
                    }
                };
            } catch {
                playerData.clan = null;
            }

            return res.json(playerData);
        }

        return res.status(response.status).json({
            "Error": [
                {
                    "message": `API request failed with status code: ${response.status}`
                }
            ]
        });

    } catch (error) {
        return res.status(500).json({
            "Error": [
                {
                    "message": `An unexpected error occurred: ${error.message}`
                }
            ]
        });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

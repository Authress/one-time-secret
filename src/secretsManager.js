
const { DynamoDB } = require('aws-sdk');
const { DateTime } = require('luxon');

const logger = require('./logger');

const dynamoDbTable = 'VanishingKeys-secrets-prod';

const dynamoDbClient = new DynamoDB.DocumentClient();

class SecretsManager {
  async createSecret(secretId, encryptedSecret, ttlDuration) {
    const now = DateTime.utc();
    const params = {
      TableName: dynamoDbTable,
      Item: {
        secretId,
        encryptedSecret,
        createdTime: now.toISO(),
        lastUpdated: now.toISO(),
        consumedAtTime: null,
        TTL: Math.round(now.plus(ttlDuration).toSeconds())
      },
      ConditionExpression: 'attribute_not_exists(secretId)'
    };

    try {
      await dynamoDbClient.put(params).promise();
    } catch (error) {
      logger.log({ title: 'Failed to store secret', level: 'ERROR', error, secretId, encryptedSecret, ttlDuration });
      if (error.code !== 'ConditionalCheckFailedException') {
        throw error;
      }
    }
  }

  async fetchAndDeleteSecret(secretId) {
    const now = DateTime.utc();

    const getParams = {
      TableName: dynamoDbTable,
      Key: {
        secretId
      }
    };

    const result = await dynamoDbClient.get(getParams).promise();
    if (result.Item?.TTL && DateTime.fromSeconds(result.Item.TTL) < DateTime.utc()) {
      return null;
    }

    const params = {
      TableName: dynamoDbTable,
      Key: { secretId },
      ConditionExpression: 'attribute_exists(secretId)',
      UpdateExpression: 'set #TTL = :TTL, #consumedAtTime = :consumedAtTime',
      ExpressionAttributeNames: {
        '#TTL': 'TTL',
        '#consumedAtTime': 'consumedAtTime'
      },
      ExpressionAttributeValues: {
        ':TTL': Math.round(now.plus({ seconds: 30 }).toSeconds()),
        ':consumedAtTime': now.toISO()
      },
      ReturnValues: 'ALL_NEW'
    };

    try {
      const updatedResult = await dynamoDbClient.update(params).promise();
      return updatedResult.Attributes;
    } catch (error) {
      if (error.code === 'ConditionalCheckFailedException') {
        return null;
      }
      logger.log({ title: 'Failed to fetch secret', level: 'ERROR', error, secretId });
      throw error;
    }
  }

  async deleteSecret(secretId) {
    const params = {
      TableName: dynamoDbTable,
      Key: {
        secretId
      }
    };

    try {
      await dynamoDbClient.delete(params).promise();
    } catch (error) {
      if (error.code === 'ConditionalCheckFailedException') {
        return;
      }
      logger.log({ title: 'Failed to delete secret', level: 'ERROR', secretId, params, error });
      throw error;
    }
  }
}

module.exports = new SecretsManager();

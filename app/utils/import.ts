import { message } from 'antd';
import _ from 'lodash';
import intl from 'react-intl-universal';

import { handleEscape, handleKeyword, handleVidStringName } from './function';

export function configToJson(payload) {
  const {
    space,
    username,
    password,
    host,
    verticesConfig,
    edgesConfig,
    taskDir,
    spaceVidType,
    batchSize
  } = payload;
  const vertexToJSON = vertexDataToJSON(
    verticesConfig,
    taskDir,
    spaceVidType,
    batchSize
  );
  const edgeToJSON = edgeDataToJSON(
    edgesConfig,
    taskDir,
    spaceVidType,
    batchSize
  );
  const files: any[] = [...vertexToJSON, ...edgeToJSON];
  const configJson = {
    version: 'v2',
    description: 'web console import',
    clientSettings: {
      retry: 3,
      concurrency: 10,
      channelBufferSize: 128,
      space: handleEscape(space),
      connection: {
        user: username,
        password,
        address: host,
      },
    },
    logPath: `${taskDir}/import.log`,
    files,
  };
  return configJson;
}

export function edgeDataToJSON(
  config: any,
  taskDir: string,
  spaceVidType: string,
  batchSize?: string,
) {
  const files = config.map(edge => {
    const edgePorps: any[] = [];
    _.sortBy(edge.props, t => t.mapping).forEach(prop => {
      switch (prop.name) {
        case 'rank':
          if (prop.mapping !== null) {
            edge.rank = {
              index: prop.mapping,
            };
          }
          break;
        case 'srcId':
          edge.srcVID = {
            index: indexJudge(prop.mapping, prop.name),
            type: spaceVidType === 'INT64' ? 'int' : 'string',
          };
          break;
        case 'dstId':
          edge.dstVID = {
            index: indexJudge(prop.mapping, prop.name),
            type: spaceVidType === 'INT64' ? 'int' : 'string',
          };
          break;
        default:
          if (prop.mapping === null && prop.isDefault) {
            break;
          }
          const _prop = {
            name: handleEscape(prop.name),
            type: prop.type,
            index: indexJudge(prop.mapping, prop.name),
          };
          edgePorps.push(_prop);
      }
    });
    const fileName = edge.file.name.replace('.csv', '');
    const edgeConfig = {
      path: edge.file.path,
      failDataPath: `${taskDir}/err/${fileName}Fail.csv`,
      batchSize: Number(batchSize) || 60,
      type: 'csv',
      csv: {
        withHeader: false,
        withLabel: false,
      },
      schema: {
        type: 'edge',
        edge: {
          name: handleEscape(edge.type),
          srcVID: edge.srcVID,
          dstVID: edge.dstVID,
          rank: edge.rank,
          withRanking: edge.rank?.index !== undefined,
          props: edgePorps,
        },
      },
    };
    return edgeConfig;
  });
  return files;
}

export function vertexDataToJSON(
  config: any,
  taskDir: string,
  spaceVidType: string,
  batchSize?: string
) {
  const files = config.map(vertex => {
    const tags = vertex.tags.map(tag => {
      const props = tag.props
        .sort((p1, p2) => p1.mapping - p2.mapping)
        .map(prop => {
          if (prop.mapping === null && prop.isDefault) {
            return null;
          }
          return {
            name: handleEscape(prop.name),
            type: prop.type,
            index: indexJudge(prop.mapping, prop.name),
          };
        });
      const _tag = {
        name: handleEscape(tag.name),
        props: props.filter(prop => prop),
      };
      return _tag;
    });
    const fileName = vertex.file.name.replace('.csv', '');
    const vertexConfig: any = {
      path: vertex.file.path,
      failDataPath: `${taskDir}/err/${fileName}Fail.csv`,
      batchSize: Number(batchSize) || 60,
      type: 'csv',
      csv: {
        withHeader: false,
        withLabel: false,
      },
      schema: {
        type: 'vertex',
        vertex: {
          vid: {
            index: indexJudge(vertex.idMapping, 'vertexId'),
            type: spaceVidType === 'INT64' ? 'int' : 'string',
          },
          tags,
        },
      },
    };
    return vertexConfig;
  });
  return files;
}

export function indexJudge(index: number | null, name: string) {
  if (index === null) {
    message.error(`${name} ${intl.get('import.indexNotEmpty')}`);
    throw new Error();
  }
  return index;
}

export function getStringByteLength(str: string) {
  let bytesCount = 0;
  const len = str.length;
  for (let i = 0, n = len; i < n; i++) {
    const c = str.charCodeAt(i);
    if ((c >= 0x0001 && c <= 0x007e) || (c >= 0xff60 && c <= 0xff9f)) {
      bytesCount += 1;
    } else {
      bytesCount += 2;
    }
  }
  return bytesCount;
}

export function createTaskID(instanceId: string) {
  return `${instanceId}.${new Date().getTime()}`;
}

export function getGQLByConfig(payload) {
  const { verticesConfig, edgesConfig, spaceVidType } = payload;
  const NGQL: string[] = [];
  verticesConfig.forEach(vertexConfig => {
    if (vertexConfig.idMapping === null) {
      message.error(`vertexId ${intl.get('import.indexNotEmpty')}`);
      throw new Error();
    }
    const csvTable = vertexConfig.file.content;
    vertexConfig.tags.forEach(tag => {
      csvTable.forEach(columns => {
        const tagField: string[] = [];
        const values: any[] = [];
        if (!tag.name) {
          message.error(`Tag ${intl.get('import.notEmpty')}`);
          throw new Error();
        }
        tag.props.forEach(prop => {
          if (prop.mapping === null && !prop.isDefault) {
            message.error(`${prop.name} ${intl.get('import.indexNotEmpty')}`);
            throw new Error();
          }
          if (prop.mapping !== null) {
            // HACK: Processing keyword
            tagField.push(handleKeyword(prop.name));
            const value =
              prop.type === 'string'
                ? `"${columns[prop.mapping]}"`
                : columns[prop.mapping];
            values.push(value);
          }
        });
        NGQL.push(
          `INSERT VERTEX ${handleKeyword(tag.name)}` +
            `(${tagField}) VALUES ${handleVidStringName(
              columns[vertexConfig.idMapping],
              spaceVidType,
            )}:(${values})`,
        );
      });
    });
  });
  edgesConfig.forEach(edgeConfig => {
    const csvTable = edgeConfig.file.content;
    csvTable.forEach(columns => {
      const edgeField: string[] = [];
      const values: any[] = [];
      if (!edgeConfig.type) {
        message.error(`edgeType ${intl.get('import.notEmpty')}`);
        throw new Error();
      }
      edgeConfig.props.forEach(prop => {
        if (prop.mapping === null && prop.name !== 'rank' && !prop.isDefault) {
          message.error(`${prop.name} ${intl.get('import.indexNotEmpty')}`);
          throw new Error();
        }
        if (
          prop.name !== 'srcId' &&
          prop.name !== 'dstId' &&
          prop.name !== 'rank' &&
          prop.mapping !== null
        ) {
          // HACK: Processing keyword
          edgeField.push(handleKeyword(prop.name));
          const value =
            prop.type === 'string'
              ? `"${columns[prop.mapping]}"`
              : columns[prop.mapping];
          values.push(value);
        }
      });
      const rank =
        edgeConfig.props[2].mapping === null
          ? ''
          : `@${columns[edgeConfig.props[2].mapping]}`;
      NGQL.push(
        `INSERT EDGE ${handleKeyword(edgeConfig.type)}` +
          `(${edgeField.join(',')}) VALUES ${handleVidStringName(
            columns[edgeConfig.props[0].mapping],
            spaceVidType,
          )} -> ${handleVidStringName(
            columns[edgeConfig.props[1].mapping],
            spaceVidType,
          )} ${rank}:(${values})`,
      );
    });
  });
  return NGQL;
}

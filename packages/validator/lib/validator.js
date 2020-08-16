'use strict';

const specsStructure = {
  'servers': {
    '__maxSize': 1,
    '__arrayItem': {
      'url': {
        '__regexp': '^(https?|ftp)://[^\\s/$.?#].[^\\s]*$'
      },
    },
  },
  'paths': {
    '__keyRegexp': '^\\/[^\\s\'"\\\\]+$',
    '__conditions': [
      {
        '__if': {
          '__this': '(?<={)[^\\/{}]+(?=})'
        },
        '__then': {
          '__objectItem': {
            'parameters': {
              '__any': {
                'name': {
                  '__regexp': '^__match$'
                }
              }
            }
          }
        }
      }
    ],
    '__objectItem': {
      '__keyRegexp': '^(get|post)$',
      '__objectItem': {
        'parameters': {
          '__arrayItem': {
            'name': {},
            'in': {
              '__regexp': '^(path|query|header|cookie)$'
            },
          },
        }
      }
    }
  },
  'components': {
    'securitySchemes': {
      '__keyRegexp': '^[^\\s\'"\\\\]+$',
      '__objectItem': {
        'type': {
          '__regexp': '^(apiKey|http)$',
          '__level': 'error'
        },
        '__conditions': [
          {
            '__if': {
              'type': '^apiKey$'
            },
            '__then': {
              'name': {}
            }
          },
          {
            '__if': {
              'type': '^http$'
            },
            '__then': {
              'scheme': {
                '__regexp': '^(Basic|Bearer)$',
                '__level': 'error'
              }
            }
          },
          {
            '__require': {
              '/security.__this_name': {}
            }
          }
        ],
        'in': {
          '__regexp': '^(query|header|cookie)$'
        },
      }
    }
  },
  'security': {
    '__keyRegexp': '^[^\\s\'"\\\\]+$',
    '__objectItem': {
      '__arrayItem': {},
      '__unique': {},
      '__conditions': [
        {
          '__require': {
            '/components.securitySchemes.__this_name': {}
          }
        }
      ]
    }
  }
};

function getLastParamName(paramPath) {
  const lastDotIndex = paramPath.lastIndexOf('.');
  let paramName = paramPath;

  if (lastDotIndex >= 0) {
    paramName = paramPath.slice(lastDotIndex + 1);
  }

  return paramName;
}

function replaceConditionalMatch(match, specs) {
  let parsedSpecs = {};

  for (const key of Object.keys(specs)) {
    if (key === '__conditions') {
      continue;
    }

    let newKey = key.replace(/__match/g, match);
    parsedSpecs[newKey] = typeof specs[key] === 'string' ? specs[key].replace(/__match/g, match) : replaceConditionalMatch(match, specs[key]);
  }

  return parsedSpecs;
}

function getParam(searchedParamPath, currentPath, specs, specsRoot) {
  let workingDir = specs;
  let requiredPath = '';

  if (searchedParamPath[0] === '/') {
    searchedParamPath = searchedParamPath.slice(1);
    workingDir = specsRoot;
    requiredPath = searchedParamPath;
  } else {
    requiredPath = `${currentPath}${currentPath ? '.' : ''}${searchedParamPath}`;
  }

  let thisName = getLastParamName(currentPath);
  requiredPath = requiredPath.replace(/__this_name/g, thisName);

  while (searchedParamPath.length) {
    if (searchedParamPath.startsWith('__this_name')) {
      searchedParamPath = searchedParamPath.replace('__this_name', '');

      if (!workingDir[thisName]) {
        return `Missing parameter ${requiredPath}`;
      }

      workingDir = workingDir[thisName];

      if (searchedParamPath.startsWith('.')) {
        searchedParamPath = searchedParamPath.replace('.', '');
      }
    } else {
      const dotIndex = searchedParamPath.indexOf('.');
      let paramName = searchedParamPath;

      if (dotIndex > 0) {
        paramName = searchedParamPath.substr(0, dotIndex);
      }

      searchedParamPath = searchedParamPath.replace(paramName, '');

      if (searchedParamPath.startsWith('.')) {
        searchedParamPath = searchedParamPath.replace('.', '');
      }

      if (!workingDir[paramName]) {
        return `Missing parameter ${requiredPath}`;
      }

      workingDir = workingDir[paramName];
    }
  }

  return workingDir;
}

function validateSpecs(specs, specsStruct, paramPath, specsRoot) {
  let messages = [];
  let valid = true;
  let checkExtraFields = true;
  let conditionalParams = [];

  for (const key of Object.keys(specsStruct)) {
    if (key === '__conditions') {
      for (const condition of specsStruct[key]) {
        if (condition['__if']) {
          const paramName = Object.keys(condition['__if'])[0];
          const paramValue = condition['__if'][paramName];
          const thenParamName = Object.keys(condition['__then'])[0];

          if (paramName === '__this') {
            for (const thisName of Object.keys(specs)) {
              if (!thisName) {
                continue;
              }

              let matches = thisName.match(new RegExp(paramValue, 'g'));

              if (matches) {
                for (let param of matches) {
                  let parsedSpecs = replaceConditionalMatch(param, condition['__then']);
                  let result = validateSpecs(specs[thisName], parsedSpecs, `${paramPath}${paramPath ? '.' : ''}${thisName}`, specsRoot);

                  if (!result.valid) {
                    messages.push({ level: 'error', message: `Condition in ${paramPath}${paramPath ? '.' : ''}${thisName} is not met with ${param}` });
                    valid = false;
                  }
                }
              }
            }
          } else if (specs[paramName]) {
            if (specs[paramName].match(new RegExp(paramValue))) {
              if (specs[thenParamName]) {
                conditionalParams.push(thenParamName);

                if (!Object.keys(condition['__then'][thenParamName]).length) {
                  continue;
                }

                let result = validateSpecs(specs[thenParamName], condition['__then'][thenParamName], `${paramPath}${paramPath ? '.' : ''}${thenParamName}`, specsRoot);
                messages.push(...result.messages);

                if (!result.valid) {
                  valid = false;
                }
              } else {
                valid = false;
                messages.push({ level: 'error', message: `Missing parameter ${paramPath}${paramPath ? '.' : ''}${thenParamName}`});
              }
            }
          }
        } else {
          for (let requiredParam of Object.keys(condition['__require'])) {
            let resultParam = getParam(requiredParam, paramPath, specs, specsRoot);

            if (typeof resultParam === 'string') {
              valid = false;
              messages.push({ level: 'error', message: resultParam });
            }
          }
        }
      }

      continue;
    }

    if (key === '__unique') {
      const lastDot = paramPath.lastIndexOf('.');
      let parentPath = paramPath;
      let paramName = paramPath;

      if (lastDot >= 0) {
        parentPath = paramPath.substr(0, lastDot);
        paramName = paramPath.substr(lastDot + 1);
      }

      let parent = getParam(`/${parentPath}`, paramPath, specs, specsRoot);
      let found = false;

      if (typeof parent === 'object') {
        let paramList = Array.isArray(parent) ? parent : Object.keys(parent);

        for (const param of paramList) {
          if (param === paramName) {
            if (found) {
              valid = false;
              messages.push({level: 'error', message: `Duplicate parameter ${paramName} in ${parentPath}`});
              break;
            }

            found = true;
          }
        }
      }

      continue;
    }

    if (key === '__regexp') {
      if (!specs.match(new RegExp(specsStruct[key]))) {
        let level = 'warning';

        if (specsStruct['__level']) {
          level = specsStruct['__level'];

          if (level === 'error') {
            valid = false;
          }
        }

        messages.push({ level, message: `${paramPath} is not formatted correctly` });
      }

      checkExtraFields = false;
      continue;
    }

    if (key === '__keyRegexp') {
      for (const item of Object.keys(specs)) {
        if (!item.match(new RegExp(specsStruct[key]))) {
          messages.push({ level: 'error', message: `Key ${item} in ${paramPath}${paramPath ? '.' : ''}${item} is formatted incorrectly` });
        }
      }

      checkExtraFields = false;
      continue;
    }

    if (key === '__maxSize') {
      if (specsStruct[key] < specs.length) {
        messages.push({ level: 'error', message: `${paramPath}${paramPath ? '.' : ''}${key} must contain ${specsStruct[key]} or less items` });
        valid = false;
      }

      checkExtraFields = false;
      continue;
    }

    if (key === '__arrayItem') {
      for (let i = 0; i < specs.length; i++) {
        let result = validateSpecs(specs[i], specsStruct[key], `${paramPath}[${i}]`, specsRoot);
        messages.push(...result.messages);

        if (!result.valid) {
          valid = false;
        }
      }

      checkExtraFields = false;
      continue;
    }

    if (key === '__objectItem') {
      for (const item of Object.keys(specs)) {
        let result = validateSpecs(specs[item], specsStruct[key], `${paramPath}${paramPath ? '.' : ''}${item}`, specsRoot);
        messages.push(...result.messages);

        if (!result.valid) {
          valid = false;
        }
      }

      checkExtraFields = false;
      continue;
    }

    if (key === '__level') {
      continue;
    }

    if (key === '__any') {
      if (!specs.length) {
        messages.push({ level: 'error', message: `${paramPath} can't be empty`});
        valid = false;

        continue;
      }

      let validParamFound = true;

      for (const param of specs) {
        let result = validateSpecs(param, specsStruct[key], paramPath, specsRoot);
        validParamFound = true;

        for (const message of result.messages) {
          if (!message.message.startsWith('Extra field: ')) {
            validParamFound = false;
            break;
          }
        }

        if (validParamFound) {
          break;
        }
      }

      if (!validParamFound) {
        messages.push({ level: 'error', message: `Required conditions not met in ${paramPath}`});
        valid = false;
      }

      continue;
    }

    if (!specs[key]) {
      messages.push({ level: 'error', message: `Missing parameter ${paramPath}${paramPath ? '.' : ''}${key}`});
      valid = false;

      continue;
    }

    if (!Object.keys(specsStruct[key]).length) {
      continue;
    }

    let result = validateSpecs(specs[key], specsStruct[key], `${paramPath}${paramPath ? '.' : ''}${key}`, specsRoot);
    messages.push(...result.messages);

    if (!result.valid) {
      valid = false;
    }
  }

  if (checkExtraFields) {
    for (const key of Object.keys(specs)) {
      if (!specsStruct[key] && !conditionalParams.includes(key)) {
        messages.push({ level: 'warning', message: `Extra field: ${paramPath}${paramPath ? '.' : ''}${key}` });
      }
    }
  }

  return { valid, messages };
}

function isSpecsValid(specs) {
  let parsedSpecs;

  try {
    parsedSpecs = JSON.parse(specs);
  } catch (e) {
    return { valid: false, messages: [{ level: 'error', message: `${e.name}: ${e.message}` }] };
  }

  return validateSpecs(parsedSpecs, specsStructure, '', parsedSpecs);
}

module.exports = { isSpecsValid };

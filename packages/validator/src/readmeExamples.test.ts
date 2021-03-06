import { validateJson } from './validate';
import {
  conditionNotMetMessage,
  extraFieldMessage,
  formattingMessage,
  keyFormattingMessage,
  missingParamMessage,
  sizeExceededMessage,
} from './utils/messages';

describe('readme examples', () => {
  it('basic', () => {
    const basicTemplate = `  
    {
      "server": {
        "url": {}
      },
      "component": {
        "securityScheme": {
            "in": {},
            "name": {},
            "type": {}
        }
      }
    }
    `;

    const basicValidInput = `
    {
      "server": {
        "url": "https://just.example.com"
      },
      "component": {
        "securityScheme": {
          "in": "query",
          "name": "example",
          "type": {}
        }
      }
    }
    `;

    const basicInvalidInput = `
    {
      "server": {
        "extra": {}
      },
      "component": {
        "securityScheme": {}
      }
    }
    `;

    expect(validateJson(basicValidInput, basicTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(basicInvalidInput, basicTemplate)).toMatchObject({
      valid: false,
      messages: [
        missingParamMessage('server.url'),
        missingParamMessage('component.securityScheme.in'),
        missingParamMessage('component.securityScheme.name'),
        missingParamMessage('component.securityScheme.type'),
        extraFieldMessage('server.extra'),
      ],
    });
  });

  it('regular expressions', () => {
    const regexpTemplate = `
        {
          "__keyRegexp": "^server$",
          "__objectItem": {
            "__regexp": "^(https?|ftp)://[^\\\\s/$.?#].[^\\\\s]*$"
          }
        }
      `;

    const validRegexpInput = `
      {
        "server": "https://www.google.com/"
      }
      `;

    const invalidRegexpInput = `
      {
        "invalid": "google"
      }
      `;

    expect(validateJson(validRegexpInput, regexpTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(invalidRegexpInput, regexpTemplate)).toMatchObject({
      valid: false,
      messages: [keyFormattingMessage('invalid', 'invalid'), formattingMessage('invalid')],
    });
  });

  it('arrays and objects', () => {
    const arraysObjectsTemplate = `
    {
      "server": {
        "__maxSize": 1,
        "__arrayItem": {
          "url": {
            "__regexp": "^(https?|ftp)://[^\\\\s/$.?#].[^\\\\s]*$"
          }
        }
      },
      "component": {
        "securitySchemes": {
          "__objectItem": {
            "in": {
              "__regexp": "^(query|header|cookie)$"
            },
            "name": {
              "__regexp": "^[^\\\\s'\\"\\\\\\\\]+$"
            },
            "type": {}
          }
        }
      },
      "security": {
        "__objectItem": {
          "__arrayItem": {}
        }
      }
    }
    `;

    const arraysObjectValidInput = `
      {
        "server": [
          {
            "url": "https://just.example.com"
          }
        ],
        "component": {
          "securitySchemes": {
            "scheme1": {
              "in": "query",
              "name": "example1",
              "type": {}
            },
            "scheme2": {
              "in": "query",
              "name": "example2",
              "type": {}
            }
          }
        },
        "security": {
          "scheme1": [],
          "scheme2": []
        }
      }
    `;

    const arraysObjectInvalidInput = `
      {
        "server": [
          {
            "url": "https://just.example.com"
          },
          {
            "url": "example.com"
          }
        ],
        "component": {
          "securitySchemes": {
            "scheme": {
              "in": "invalid",
              "name": {},
              "type": {}
            }
          }
        },
        "security": {
          "scheme": [
            {
              "extra": "extra"
            }
          ]
        }
      }
    `;

    expect(validateJson(arraysObjectValidInput, arraysObjectsTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(arraysObjectInvalidInput, arraysObjectsTemplate)).toMatchObject({
      valid: false,
      messages: [
        sizeExceededMessage('server', 1),
        formattingMessage('server[1].url'),
        formattingMessage('component.securitySchemes.scheme.in'),
        formattingMessage('component.securitySchemes.scheme.name'),
        extraFieldMessage('security.scheme[0].extra'),
      ],
    });
  });

  it('conditions', () => {
    const basicTemplate = `
        {
          "conditionsExample": {
            "value": {},
            "__conditions": [
              {
                "__if": {
                  "value": "^one$"
                },
                "__then": {
                  "one": {
                    "__regexp": "^This is required by one$"
                  }
                }
              },
              {
                "__if": {
                  "value": "^two$"
                },
                "__then": {
                  "two": {
                    "__regexp": "^This is required by two$"
                  }
                }
              }
            ]
          }
        }
      `;

    const validBasicSpec = `
        {
          "conditionsExample": {
            "value": "one",
            "one": "This is required by one"
          }
        }
      `;

    const invalidBasicSpec = `
      {
        "conditionsExample": {
          "value": "two",
          "one": "This is required by two"
        }
      }
      `;

    expect(validateJson(validBasicSpec, basicTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(invalidBasicSpec, basicTemplate)).toMatchObject({
      valid: false,
      messages: [missingParamMessage('conditionsExample.two'), extraFieldMessage('conditionsExample.one')],
    });

    const requireTemplate = `
      {
        "items": {
        "__objectItem": {
          "__keyRegexp": "^require[0-9]$",
          "__conditions": [
            {
              "__require": {
                "/outer.__this_name.inner": {}
              }
            }
          ]
        }
        }
      }
      `;

    const validRequireSpec = `
      {
        "items": {
          "require0": {},
          "require5": {}
        },
        "outer": {
          "require0": {
            "inner": {}
          },
          "require5": {
            "inner": {}
          }
        }
      }
      `;

    const invalidRequireSpec = `
      {
        "items": {
            "require0": {},
            "require5": {}
          },
        "outer": {
          "require0": {},
          "require1": {
            "inner": {}
          }
        }
      }
      `;

    expect(validateJson(validRequireSpec, requireTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(invalidRequireSpec, requireTemplate)).toMatchObject({
      valid: false,
      messages: [
        missingParamMessage('outer.require0.inner'),
        missingParamMessage('outer.require5.inner'),
        extraFieldMessage('outer.require1'),
      ],
    });

    const ifThenMatchesTemplate = `
      {
        "items": {
          "__objectItem": {
            "__conditions": [
              {
                "__if": {
                  "__this": "^matchedValue$"
                },
                "__rootThen": {
                  "thenItems": {
                    "byValue": {
                      "__regexp": "^__match$"
                    }
                  }
                }
              }
            ]
          },
          "__conditions": [
                  {
                      "__if": {
                          "__this_name": "^matchedKey$"
                      },
                      "__rootThen": {
                          "thenItems": {
                              "byKey": {
                                  "__regexp": "^__match$"
                              }
                          }
                      }
                  }
              ]
        },
        "thenItems": {}
      }
      `;

    const validIfThenMatchesSpec = `
      {
        "items": {
          "item1": "matchedValue",
          "matchedKey": "item2"
        },
        "thenItems": {
              "byValue": "matchedValue",
              "byKey": "matchedKey"
          }
      }
      `;

    const invalidIfThenMatchesSpec = `
      {
        "items": {
          "item1": "matchedValue",
          "matchedKey": "item2"
        },
        "thenItems": {}
      }
      `;

    expect(validateJson(validIfThenMatchesSpec, ifThenMatchesTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(invalidIfThenMatchesSpec, ifThenMatchesTemplate)).toMatchObject({
      valid: false,
      messages: [missingParamMessage('thenItems.byValue'), conditionNotMetMessage('items.matchedKey', 'matchedKey')],
    });

    const anyTemplate = `
      {
        "items": {
          "__objectItem": {
            "__keyRegexp": ".*"
          },
          "__conditions": [
            {
              "__if": {
                "__this_name": "^anyExample$"
              },
              "__rootThen": {
                "thenItems": {
                  "__any": {
                    "valid": {}
                  }
                }
              }
            }
          ]
        },
        "thenItems": {
          "item1": {},
          "item2": {},
          "item3": {}
        }
      }
      `;

    const validAnySpec = `
      {
        "items": {
          "anyExample": {}
        },
        "thenItems": {
          "item1": {},
          "item2": {
            "valid": "true"
          },
          "item3": {}
        }
      }
      `;

    const invalidAnySpec = `
        {
          "items": {
            "anyExample": {}
          },
          "thenItems": {
                "item1": {},
                "item2": {},
                "item3": {}
          }
        }
      `;

    expect(validateJson(validAnySpec, anyTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(invalidAnySpec, anyTemplate)).toMatchObject({
      valid: false,
      messages: [conditionNotMetMessage('items.anyExample', 'anyExample')],
    });

    const optionalLevelTemplate = `
      {
        "levelExample": {
          "__regexp": "^true$",
          "__level": "error"
        },
          "__optional": {
            "optionalExample": {}
          }
      }
      `;

    const validOptionalLevelSpec = `
      {
        "levelExample": "true"
      }
      `;

    const invalidOptionalLevelSpec = `
      {
        "levelExample": "false",
        "optionalExample": {}
      }
      `;

    expect(validateJson(validOptionalLevelSpec, optionalLevelTemplate)).toMatchObject({ valid: true, messages: [] });
    expect(validateJson(invalidOptionalLevelSpec, optionalLevelTemplate)).toMatchObject({
      valid: false,
      messages: [formattingMessage('levelExample', true)],
    });
  });
});

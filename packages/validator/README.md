# `@airnode/validator`

A tool capable of determining if provided OIS or `config.json` and `security.json` are valid or not.

# Usage

The validator can be run as an NPM script, by providing the paths to the JSON file that will be checked and the JSON file to use as template:
```sh
npm run validate --template="[templateFile]" --specs="[specsFile]"
```

In case specifications file is provided first, the command can be simplified to: `npm run validate [templateFile] [specsFile]`. Try it out using the example specification:
```sh
npm run validate templates/ois.json exampleSpecs/ois.specs.json
```

Validation of config and security has a separate command, in which the template is omitted:
```sh
npm run validateConfigSecurity --config="[configFile]" --security="[securityFile]"
```

Which can be simplified in the same manner as `validate` command and invoked with example specifications:
```sh
npm run validateConfigSecurity exampleSpecs/config.specs.json exampleSpecs/security.specs.json
```

# Output

Validator will print the result into console as a JSON in the following format:

```
{
    valid: boolean,
    messages: array
}
```
Where array `messages` may contain message objects:
```
{
    level: 'error' | 'warning',
    message: string
}
```

If provided specification is valid, parameter `valid` will be set to `true`, however parameter `messages` may still contain messages, but only with `level` set to `warning`. In case `valid` is `false`, there will be always one or more error messages.

# Validator templates

To make modifications to OIS format as simple as possible, validator uses JSON templates which define a valid format of specification.

## Basics

Most basic validator template can simply include names of all required parameters, which will result in validator accepting any specification that has exactly these parameters with any values.

#### Template
```json
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
```
---
#### Valid specification
```json
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
```
#### Expected output
```json
{
    "valid": true,
    "messages": []
}
```
---
#### Invalid specification
```json
{
    "server": {
        "extra": {}
    },
    "component": {
        "securityScheme": {}
    }
}
```
#### Expected output
```json
{
    "valid": false,
    "messages": [
        { "level": "error", "message": "Missing parameter server.url" },
        { "level": "error", "message": "Missing parameter component.securityScheme.in" },
        { "level": "error", "message": "Missing parameter component.securityScheme.name" },
        { "level": "error", "message": "Missing parameter component.securityScheme.type" },
        { "level": "warning", "message": "Extra field: server.extra" }
    ]
}
```
---

## Regular expressions

To ensure parameters are in correct format, regular expressions are used. Token `__regexp` means, that value of the parameter, has to match the provided regular expression. Similarly `__keyRegexp`, is checking if the key of parameter matches the regular expression.

#### Template
```json
{
	"__keyRegexp": "^server$",
	"__objectItem": {
		"__regexp": "^(https?|ftp)://[^\\s/$.?#].[^\\s]*$"
	}
}
```
---
#### Valid specification
```json
{
	"server": "https://www.google.com/"
}
```
---
#### Invalid specification
```json
{
	"invalid": "google"
}
```
#### Expected output
```json
{
	"valid": false,
	"messages": [
		{ "level": "error", "message": "Key invalid in invalid is formatted incorrectly" },
		{ "level": "warning", "message": "invalid is not formatted correctly" }
	]
}
```
---

Notice `__keyRegexp` is nested on the same level as key of the parameter it is validating, whereas `__regexp` is nested in the object, which value it is validating.

### Useful regular expressions

`^(one|two)$` - all the valid strings are `one` and `two`

`(?<={)[^\/{}]+(?=})` - anything thats between `{` and `}` (usage example at parameters in paths)

`^[^\s'"\\]+$` - any string with at least 1 character and not containing any whitespaces, `'`, `"` or `\\`

## Arrays and objects

Token `__arrayItem` means that the parameter is an array and contents of the token describe what should be the structure of the contents in the array. `maxSize` is an array specific token, which can be used to set maximal count of elements in the array.

`__objectItem` is used in combination with `__keyRegexp` or in conditions, it describes the structure of the object inside the parameter.

#### Template
```json
{
	"server": {
		"__maxSize": 1,
		"__arrayItem": {
			"url": {
				"__regexp": "^(https?|ftp)://[^\\s/$.?#].[^\\s]*$"
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
					"__regexp": "^[^\\s'\"\\\\]+$"
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
```
---
#### Valid specification
```json
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
```
---
#### Invalid specification
```json
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
```
#### Expected output
```json
{
	"valid": false,
	"messages": [
		{ "level": "error", "message": "server must contain 1 or less items" },
		{ "level": "warning", "message": "server[1].url is not formatted correctly" },
		{ "level": "warning", "message": "component.securitySchemes.scheme.in is not formatted correctly" },
		{ "level": "warning", "message": "component.securitySchemes.scheme.name is not formatted correctly" },
		{ "level": "warning", "message": "Extra field: security.scheme[0].extra" }
	] 
}
```
---

## Conditions

### Basics

Conditions are objects containing `__if` and `__then` objects, these objects are placed into array `__conditions`, which can contain any amount of condition objects. Object `__if` contains parameter name with regular expression, if the regular expression is matched in provided specification, validator will validate everything that's in the `__then` object. Here is an example of a very basic condition:

#### Template

```json
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
```
---
#### Valid specification
```json
{
  "conditionsExample": {
    "value": "one",
    "one": "This is required by one"
  }
}
```
---
#### Invalid specification
```json
{
  "conditionsExample": {
    "value": "two",
    "one": "This is required by two"
  }
}
```
#### Expected output

```json
{
  "valid": false,
  "messages": [
    { "level": "error", "message": "Missing parameter conditionsExample.two" },
    { "level": "warning", "message": "Extra field: conditionsExample.one" }
  ]
}
```
---

In this example parameter `conditionsExample.value` is required, if it's value is `one`, first condition will be checked and specification must contain parameter `conditionsExample.one` with value `This is required by one`. If `conditionsExample.one` isn't in the specification, or it's value is not `This is required by one`, validation will return an error. In the valid specification example the second condition is not checked at all because value of `conditionsExample.value` is not `two`. In the invalid specification example the second condition is applied, but parameter `conditionsExample.two` is missing from specification and since first condition is ignored (`conditionsExample.value` is not `one`) and parameter `conditionsExample.one` is not required it is labeled as extra parameter.

### Require

`__require` consists of a parameter path that validator will check and throw error if it doesn't exist. The path is relative to the location of the parameter, unless it starts with `/`, in that case it is an absolute path starting in the root of the specification. So far the `__require` functionality can be achieved by simply including the parameter in the template, the strength of `__require` becomes apparent when combined with `__this_name` keyword. `__this_name` instances in the required parameter path will be replaced with name of the parameter the condition is nested in.

#### Template
```json
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
```
---
#### Valid specification
```json
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
```
---
#### Invalid specification
```json
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
```
#### Expected output
```json
{
	"valid": false,
	"messages": [
		{ "level": "error", "message": "Missing parameter outer.require0.inner" },
		{ "level": "error", "message": "Missing parameter outer.require5.inner" },
		{ "level": "warning", "message": "Extra field: outer.require1" }
	]
}
```
---

In this example parameters inside `items` must be named `require` followed by number from 0 to 9 (determined by `__keyRegexp` parameter), `__require` condition's parameter starts with `/`, this means required parameter will be evaluated from root of the specification not from object `items`, where the condition is nested in. In both specification examples are 2 items (`require0` and `require5`), this means `__this_name` in the require parameter path will be replaced with respective parameters, which results in 2 required parameters (`outer.require0.inner` and `outer.require5.inner`).

### Root then

`__require` conditions can be evaluated from root of the specification if required parameter name starts with `/` this behaviour can be achieved in if/then conditions as well, by replacing parameter `__then` with `__rootThen`

### Regular expression matches in if/then conditions

Regular expressions are often used in `__if` parameter of condition, matched string from the regular expression can be access in `__then` object with keyword `__match`, in this case `__if` object must specify if it's matching key of parameter (`__this_name`), or it's value (`__this`).

#### Template
```json
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
```
---
#### Valid specification

```json
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
```
---
#### Invalid specification

```json
{
	"items": {
		"item1": "matchedValue",
		"matchedKey": "item2"
	},
	"thenItems": {}
}
```

#### Expected output
```json
{
	"valid": false,
	"messages": [
		{ "level": "error", "message": "Missing parameter thenItems.byValue" },
		{ "level": "error", "message": "Missing parameter items.matchedKey" }
	]
}
```
---

This example highlights differences between `__this` and `__this_name` in if/then conditions. First condition matches the value of parameter, if the value is `matchedValue`, parameter `thenItems.byValue` becomes required, since `__match` keyword was replaced with `matchedValue` in the then section. `__this_name` will match `matchedKey` and require `thenItems.byKey` parameter. Notice the different positions of both conditions, `__this` is evaluated for the object the condition is nested in, whereas `__this_name` is evaluated from object the parameter, which key will be evaluated is nested in.

### Any

Section `__then` can contain keyword `__any`, on level where array or object is expected. Validator will check every nested item/object, if none of them satisfies the `__then` section of condition, the specs will be invalid.

#### Template

```json
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
```
---
#### Valid specification

```json
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
```
---
#### Invalid specification
```json
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
```
#### Expected output
```json
{
	"valid": false,
	"messages": [
		{ "level": "error", "message": "Condition in items.anyExample is not met with anyExample" }
	]
}
```
---

This example template, will evaluate all nested objects in `thenItems`, if any of those objects is matching `__then` section of condition, the specification is valid, otherwise it will return condition not met error.

## Optional and level

Sometimes a warning, should be considered an error and vice versa, the level of the message can be adjusted with `__level` for a specific parameter. Also some parameters don't have to be in the specification, but if they are it's still fully valid specification without any errors or warnings, for this parameter `__optional` is used.

#### Template
```json
{
	"levelExample": {
		"__regexp": "^true$",
		"__level": "error"
	},
	"__optional": {
		"optionalExample": {}
	}
}
```
---
#### Valid specification

```json
{
	"levelExample": "true"
}
```
---
#### Invalid specification

```json
{
	"levelExample": "false",
	"optionalExample": {}
}
```
#### Expected output
```json
{
	"valid": false,
	"messages": [
		{ "level": "error", "message": "levelExample is not formatted correctly" }
	]
}
```
---

In invalid specification the level of formatting message is error, which results in the whole specification to be not valid, normally the formatting message is only a warning. Also in valid specification there is no message about missing parameter `optionalExample` and in invalid specification there is no `extra parameter` message, which means validator doesn't care if `optionalExample` is or is not in the specification.

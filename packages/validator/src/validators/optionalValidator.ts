import * as utils from '../utils/utils';
import { validateSpecs } from '../validator';
import { Roots, Log } from '../types';

/**
 * Validates optional parameters in specification
 * @param specs - specification that is being validated
 * @param template - must be on the same level as specs
 * @param paramPath - string of parameters separated by ".", representing path to current specs location
 * @param nonRedundantParams - object containing all required and optional parameters that are being used
 * @param roots - roots of specs and nonRedundantParams
 * @param paramPathPrefix - in case roots are not the top layer parameters, parameter paths in messages will be prefixed with paramPathPrefix
 * @returns errors and warnings that occurred in validation of provided specification
 */
export function validateOptional(
  specs: any,
  template: any,
  paramPath: string,
  nonRedundantParams: any,
  roots: Roots,
  paramPathPrefix: string
): Log[] {
  const messages: Log[] = [];

  for (const optionalItem of Object.keys(template)) {
    for (const item of Object.keys(specs)) {
      // in the specs might be other parameters, only the optional ones are validated here
      if (item === optionalItem) {
        nonRedundantParams[item] = utils.getEmptyNonRedundantParam(item, template, nonRedundantParams, specs[item]);

        const result = validateSpecs(
          specs[item],
          template[item],
          `${paramPath}${paramPath ? '.' : ''}${item}`,
          nonRedundantParams[item],
          roots,
          paramPathPrefix
        );
        messages.push(...result.messages);
      }
    }
  }

  return messages;
}

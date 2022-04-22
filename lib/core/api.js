/* eslint-disable no-param-reassign */
/**
 * Copyright (c) 2014, Tidepool Project
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the associated License, which is identical to the BSD 2-Clause
 * License as published by the Open Source Initiative at opensource.org.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the License for more details.
 *
 * You should have received a copy of the License along with this program; if
 * not, you can obtain one from Tidepool Project at tidepool.org.
 */

import _ from 'lodash';
import async from 'async';
import {format} from 'util';
import crypto from 'crypto';
import sundial from 'sundial';
import {v4 as uuidv4} from 'uuid';
import isElectron from 'is-electron';
import os from 'os';
import fs from 'fs';

import bows from 'bows';
// Wrapper around the Tidepool client library
import createTidepoolClient from 'tidepool-platform-client';

import ErrorMessages from '../../app/constants/errorMessages';
import builder from '../objectBuilder';
import localStore from './localStore';
import rollbar from '../../app/utils/rollbar';
import * as actionUtils from '../../app/actions/utils';
import personUtils from './personUtils';
import superagent from 'superagent';

// eslint-disable-next-line no-console
const log = isElectron() ? bows('Api') : console.log;

// for cli tools running in node
if (typeof localStore === 'function') {
    localStore = localStore({});
}

let tidepool;
let patient = {};
let myPrediServer = '';

const api = {
    log,
};

// ----- Api Setup -----

// synchronous!
api.create = (options) => {
    // eslint-disable-next-line no-console
    const tidepoolLog = isElectron() ? bows('Tidepool') : console.log;
    tidepool = createTidepoolClient({
        host: options.apiUrl,
        uploadApi: options.uploadUrl,
        dataHost: options.dataUrl,
        log: {
            warn: tidepoolLog,
            info: tidepoolLog,
            debug: tidepoolLog,
        },
        localStore,
        metricsSource: 'uploader',
        metricsVersion: options.version,
        sessionTrace: uuidv4(),
    });

    api.tidepool = tidepool;
};

// asynchronous!
api.init = (cb) => {
    api.tidepool.initialize(cb);
};

// ----- Config -----
api.setHosts = (hosts) => {
    if (hosts.API_URL) {
        tidepool.setApiHost(hosts.API_URL);
    }
    if (hosts.UPLOAD_URL) {
        tidepool.setUploadHost(hosts.UPLOAD_URL);
    }
    if (hosts.DATA_URL) {
        tidepool.setDataHost(hosts.DATA_URL);
    }
    if (hosts.BLIP_URL) {
        tidepool.setBlipHost(hosts.BLIP_URL);
    }

    if (rollbar && rollbar.configure) {
        rollbar.configure({
            payload: {
                environment: hosts.environment,
            },
        });
    }
};

api.makeBlipUrl = (tail) => tidepool.makeBlipUrl(tail);

// ----- User -----

api.user = {};

api.user.initializationInfo = (cb) => {
    const userId = tidepool.getUserId();
    async.series([
        api.user.account,
        api.user.loggedInProfile,
        api.user.getUploadGroups,
        api.user.getAssociatedAccounts,
        (callback) => {
            api.clinics.getClinicsForClinician(userId, callback);
        },
    ], cb);
};

api.user.login = (user, options, cb) => {
    api.log('POST /auth/login');

    patient = {};
    myPrediServer = '';

    login(user, options, (err, data) => {
        if (err) {
            return cb(err);
        }
        const dataX = {
            'userid': data.userid,
            'user': {
                'emailVerified': true,
                'emails': [data.user.email],
                'termsAccepted': '2021-11-15T10:44:16+01:00',
                'userid': data.userid,
                'username': data.user.email,
                'myprediUsername': patient.username,
                'myprediPassword': patient.password,
                'myprediServer': user.server,
            }
        };

        if (rollbar && rollbar.configure) {
            rollbar.configure({
                payload: {
                    person: {
                        id: data.userid,
                        email: user.username,
                        username: user.username,
                    },
                },
            });
        }
        return cb(null, dataX);
    });


    /*
    tidepool.login(user, options, (err, data) => {
      if (err) {
        return cb(err);
      }
      if (rollbar && rollbar.configure) {
        rollbar.configure({
          payload: {
            person: {
              id: data.userid,
              email: user.username,
              username: user.username,
            },
          },
        });
      }
      return cb(null, data);
    });
     */
};

/**
 * Login user to the Tidepool platform
 *
 * @param user object with a username and password to login
 * @param options (optional) object with `remember` boolean attribute
 * @param cb
 * @returns {cb}  cb(err, response)
 */
function login(user, options, cb) {
    options = options || {};
    if (typeof options === 'function') {
        cb = options;
        options = {};
    }

    if (user.server == null) {
        return cb({status: 401, message: 'Must specify a username'});
    }
    if (user.server.length == 0){
        return cb({status: 401, message: 'Must specify a username'});
    }

    myPrediServer = 'https://' + user.server + '/ecare-portal/api/';

    if (user.username == null) {
        return cb({status: 401, message: 'Must specify a username'});
    }
    if (user.username.length == 0){
        return cb({status: 401, message: 'Must specify a username'});
    }

    if (user.password == null) {
        return cb({status: 401, message: 'Must specify a password'});
    }
    if (user.password.length == 0){
        return cb({status: 401, message: 'Must specify a password'});
    }

    getToken(user.username, user.password, (err, data) => {
        if (err != null){
            return cb(err);
        }
        superagent
            .post(myPrediServer + 'authentification/patient?login=' + user.username + '&password=' + user.password)
            .set('MyPredi_Rest_ApiKey', data.token)
            .retry()
            .end(function (err, res) {
                if (err != null) {
                    return cb(err);
                }
                patient = res.body.response;
                patient.username = user.username;
                patient.password = user.password;
                return cb(null, {userid: patient.id, user: patient});
            });
    });

}

function getPersonalSensorList(sessionInfo, cb) {
    getToken(patient.username, patient.password, (err, data) => {
        if (err != null){ return err;}
        superagent.get(myPrediServer + 'sensor/generatePersonalSensorList')
            .set('MyPredi_Rest_ApiKey', data.token)
            .retry()
            .end(
                function (err, res) {
                    if (err != null) {
                        return cb(err, null);
                    }
                    var sensors = res.body.response;
                    var sensorAlreadyAssigned = false;
                    var sensorSelected = null;
                    for (const sensor of sensors){
                        if (sensor.serialNumber == sessionInfo.deviceSerialNumber && sensor.patientId == patient.id){
                            sensorAlreadyAssigned = true;
                            sensorSelected = sensor;
                            break;
                        }
                    }
                    return cb(null, {
                        sensors : sensors,
                        isAlreadyAssignedToActualPatient : sensorAlreadyAssigned,
                        sensorSelected : sensorSelected
                    });
                });
    });
}

function addOrUpdateSensorInServer(sensor) {
    getToken(patient.username, patient.password, (err, data) => {
        if (err != null){ return err;}
        superagent.post(myPrediServer + 'sensor/AddOrUpdatePersonalSensor')
            .set('MyPredi_Rest_ApiKey', data.token)
            .send([sensor])
            .end(
                function (err, res) {
                    if (err != null) {
                        console.log(err);
                    }
                    console.log('addOrUpdateSensorInServer OK');
                });
    });
}

function getSensorFromSessionInfo(sessionInfo){
    var brandLabel = sessionInfo.deviceManufacturers[0] == undefined ? "Unknown" : sessionInfo.deviceManufacturers[0];
    const now = Date.now().valueOf();
    return {
        "id": "capteur_personnel_" + sessionInfo.deviceId,
        "typeId": "SENSOR_TYPE_GLUCOMETER_PERSONAL",
        "typeLabel": "Glucomètre capillaire personnel",
        "ecareTag": "GLU-UPLOADER-" + sessionInfo.deviceSerialNumber,
        "macAddress": "MAC-UPLOADER-"+ sessionInfo.deviceId,
        "serialNumber": sessionInfo.deviceSerialNumber,
        "personal": 1,
        "modelId": "SENSOR_MODEL_" + brandLabel,
        "modelLabel": sessionInfo.deviceModel,
        "patientId": patient.id,
        "brandLabel": brandLabel,
        "lastConnection": now,
        "assignmentDate": now,
        "lastUpdate": now
    };
}

function getPeriodList(cb) {
    getToken(patient.username, patient.password, (err, data) => {
        if (err != null){ return err;}
        superagent.get(myPrediServer + 'period/generatePeriodList')
            .set('MyPredi_Rest_ApiKey', data.token)
            .retry()
            .end(
                function (err, res) {
                    if (err != null) {
                        return cb(err, null);
                    }
                    return cb(null, res.body.response);
                });
    });
}

function pushMeasure(measureList, cb) {
    getToken(patient.username, patient.password, (err, data) => {
        if (err != null){ return err;}
        var fromDate = measureList[0].date;
        superagent.post(myPrediServer + 'measure/AddOrUpdateMeasure')
            .set('MyPredi_Rest_ApiKey', data.token)
            .timeout(180 * 1000)
            .send(
                {
                    "fromDate": fromDate,
                    //"fromDate": 1650547339000,
                    "patientIdServer": patient.id,
                    "measureList": measureList
                }
            )
            .retry()
            .end(
                function (err, res) {
                    if (err != null) {
                        return cb(err, null);
                    }
                    return cb(null, res.body.response);
                });
    });
}

/**
 *
 * @param user
 * @param options
 * @param cb
 * @returns {cb}  cb(err, response)
 */
const API_TOKEN = '0.^Z/[|a$MxR_<crLy: UD9We~qqmqf,t1H*9}s!B`*Vi;I?avA?;*T? 9!Dwa++';

function getToken(username, password, cb) {
    superagent
        .get(myPrediServer + 'token/getPatientToken?login=' + username + '&password=' + password)
        .set('MyPredi_Rest_ApiKey', API_TOKEN)
        .retry()
        .end(
            function (err, res) {
                if (err != null) {
                    return cb(err);
                }

                if (res.body.status != 200){
                    return cb({status: 401, message: res.body.message});
                }
                //localStore.removeItem(TOKEN_LOCAL_KEY);
                var token = res.body.response;
                //localStore.setItem(TOKEN_LOCAL_KEY, token);
                return cb(null, {token: token});
            });

}

api.user.loginExtended = (user, options, cb) => {
    async.series([
        api.user.login.bind(null, user, options),
        api.user.loggedInProfile,
        api.user.getUploadGroups,
        //api.user.getAssociatedAccounts,
    ], cb);
};

api.user.account = (cb) => {
    api.log('GET /auth/user');
    tidepool.getCurrentUser((err, user) => {
        // the rewire plugin messes with default export in tests
        if (rollbar && rollbar.configure) {
            rollbar.configure({
                payload: {
                    person: {
                        id: user.userid,
                        email: user.username,
                        username: user.username,
                    },
                },
            });
        }
        cb(err, user);
    });
};

api.user.loggedInProfile = (cb) => {
    //api.log(`GET /metadata/${tidepool.getUserId()}/profile`);
    api.log(`GET /metadata/b348d8848e/profile`);
    /*
    tidepool.findProfile('b348d8848e', (err, profile) => {
      if (err) {
        return cb(err);
      }
      return cb(null, profile);
    });

     */
    return cb(null, {
        fullName: patient.firstname + ' ' + patient.lastname,
        patient: {
            birthday: '1992-01-25',
            diagnosisDate: '2015-11-20',
            diagnosisType: 'other',
            isOtherPerson: true,
            fullName: patient.firstname + ' ' + patient.lastname,
            targetDevices: [
                'accuchekusb',
                'bayercontour',
                'abbottfreestylelibre',
                'bayercontournext',
                'medtronic600',
                'omnipod',
            ],
            targetTimezone: 'Europe/Paris'
        }
    });
};

api.user.profile = (userId, cb) => {
    api.log(`GET /metadata/${userId}/profile`);
    tidepool.findProfile(userId, (err, profile) => {
        if (err) {
            return cb(err);
        }
        return cb(null, profile);
    });
};

api.user.addProfile = (userId, profile, cb) => {
    api.log(`PUT /metadata/${userId}/profile`);
    tidepool.addOrUpdateProfile(userId, profile, (err, response) => {
        if (err) {
            return cb(err);
        }
        return cb(null, response);
    });
};

api.user.updateProfile = (userId, updates, cb) => {
    api.user.profile(userId, (err, profile) => {
        if (err) {
            return cb(err);
        }
        const currentEmail = _.get(profile, 'emails[0]');
        const newProfile = actionUtils.mergeProfileUpdates(profile, updates);
        const emails = _.get(updates, 'emails');
        // check to see if we have a single email address that also needs to be updated
        if (_.isArray(emails) && emails.length === 1 && emails[0] !== currentEmail) {
            return async.series([
                (callback) => tidepool.updateCustodialUser({
                    username: emails[0],
                    emails,
                }, userId, callback),
                (callback) => tidepool.addOrUpdateProfile(userId, newProfile, callback),
                (callback) => tidepool.signupStart(userId, callback),
            ], (error, results) => {
                if (error) {
                    return cb(error);
                }
                return cb(null, results[1]);
            });
        }
        return tidepool.addOrUpdateProfile(userId, newProfile, cb);
    });
};

api.user.logout = (cb) => {
    api.log('POST /auth/logout');
    fs.writeFile('./file.json','', 'utf-8', (error, data) => {
        if (error){
            console.error('error: ' + error);
        }
    });
    return cb(null);

    if (!tidepool.isLoggedIn()) {
        api.log('Not authenticated, but still destroying session for just in cases...');
        tidepool.destroySession();
        return;
    }
    tidepool.logout((err) => {
        if (err) {
            api.log('Error while logging out but still destroying session...');
            tidepool.destroySession();
            return cb(err);
        }
        return cb(null);
    });
};

api.user.getUploadGroups = (cb) => {
    api.log(`GET /metadata/users/${patient.id}`);

    return cb(null, [
        {
            userid: patient.id,
            profile: {
                fullName: patient.firstname + ' ' + patient.lastname,
                patient: {
                    birthday: '1992-01-25',
                    diagnosisDate: '2015-11-20',
                    diagnosisType: 'other',
                    isOtherPerson: true,
                    fullName: patient.firstname + ' ' + patient.lastname,
                    targetDevices:
                        [
                            'accuchekusb',
                            'bayercontour',
                            'abbottfreestylelibre',
                            'bayercontournext',
                            'medtronic600',
                            'omnipod',
                        ],
                    targetTimezone: 'Europe/Paris'
                }
            },
        }
    ]);

    /*
    async.parallel([
      (callback) => tidepool.getAssociatedUsersDetails(userId, callback),
      (callback) => tidepool.findProfile(userId, callback),
    ], (err, results) => {
      if (err) {
        cb(err);
      }
      const [users, profile] = results;

      let uploadUsers = _.filter(users, (user) => _.has(user.trustorPermissions, 'upload'));

      uploadUsers = _.map(uploadUsers, (user) => {
        // eslint-disable-next-line no-param-reassign
        user.permissions = user.trustorPermissions;
        // eslint-disable-next-line no-param-reassign
        delete user.trustorPermissions;
        return user;
      });

      // getAssociatedUsersDetails doesn't include the current user
      uploadUsers.push({
        userid: userId,
        profile,
        permissions: { root: {} },
      });

      const sortedUsers = _.sortBy(uploadUsers, (group) => group.userid === userId);
      return cb(null, sortedUsers);
    });

     */
};

api.user.createCustodialAccount = (profile, cb) => {
    const userId = tidepool.getUserId();

    api.log(`POST /auth/user/${userId}/user`);
    tidepool.createCustodialAccount(profile, (err, account) => cb(err, account));
};

// Get all accounts associated with the current user
api.user.getAssociatedAccounts = (cb) => {
    api.log('GET /patients');

    tidepool.getAssociatedUsersDetails(tidepool.getUserId(), (err, users) => {
        if (err) {
            return cb(err);
        }

        // Filter out viewable users, data donation, and care team accounts separately
        const viewableUsers = [];
        const dataDonationAccounts = [];
        const careTeam = [];

        _.each(users, (user) => {
            if (personUtils.isDataDonationAccount(user)) {
                dataDonationAccounts.push({
                    userid: user.userid,
                    email: user.username,
                    status: 'confirmed',
                });
            } else if (!_.isEmpty(user.trustorPermissions)) {
                // These are the accounts that have shared their data
                // with a given set of permissions.
                user.permissions = user.trustorPermissions;
                delete user.trustorPermissions;
                viewableUsers.push(user);
            } else if (!_.isEmpty(user.trusteePermissions)) {
                // These are accounts with which the user has shared access to their data, exluding the
                // data donation accounts
                user.permissions = user.trusteePermissions;
                delete user.trusteePermissions;
                careTeam.push(user);
            }
        });

        return cb(null, {
            patients: viewableUsers,
            dataDonationAccounts,
            careTeam,
        });
    });
};

// ----- Patient -----

api.patient = {};

// Get a user's public info
function getPerson(userId, cb) {
  const person = { userid: userId };

  tidepool.findProfile(userId, (err, profile) => {
    if (err) {
      // Due to existing account creation anti-patterns, coupled with automatically sharing our demo
      // account with new VCAs, we can end up with 404s that break login of our demo user when any
      // VCA account has not completed their profile setup. Until this is addressed on the backend,
      // we can't callback an error for 404s.
      if (err.status === 404) {
        person.profile = null;
        return cb(null, person);
      }
      return cb(err);
    }

    person.profile = profile;
    return cb(null, person);
  });
}

function setPatientSettings(person, cb) {
  api.metadata.settings.get(person.userid, (err, settings) => {
    if (err) {
      return cb(err);
    }

    person.settings = settings || {};

    return cb(null, person);
  });
}

/*
 * Not every user is a "patient".
 * Get the "patient" and attach the logged in users permissons
 */
function getPatient(patientId, cb) {
  return getPerson(patientId, (err, person) => {
    if (err) {
      return cb(err);
    }

    if (!personUtils.isPatient(person)) {
      return cb();
    }

    // Attach the settings for the patient
    return setPatientSettings(person, cb);
  });
}

api.patient.get = function (patientId, cb) {
  api.log(`GET /patients/${patientId}`);

  getPatient(patientId, (err, patient) => {
    if (err) {
      return cb(err);
    }

    if (!patient) {
      // No patient profile for this user yet, return "not found"
      return cb({ status: 404, response: 'Not found' });
    }

    return cb(null, patient);
  });
};

// ----- Metadata -----

api.metadata = {};

api.metadata.settings = {};

api.metadata.settings.get = function (patientId, cb) {
  api.log(`GET /metadata/${patientId}/settings`);

  // We don't want to fire an error if the patient has no settings saved yet,
  // so we check if the error status is not 404 first.
  tidepool.findSettings(patientId, (err, payload) => {
    if (err && err.status !== 404) {
      return cb(err);
    }

    const settings = payload || {};

    return cb(null, settings);
  });
};

// ----- Upload -----

api.upload = {};

api.upload.getVersions = (cb) => {
  api.log('GET /info');
  tidepool.checkUploadVersions((err, resp) => {
    if (err) {
      if (!navigator.onLine) {
        const error = new Error(ErrorMessages.E_OFFLINE);
        error.originalError = err;
        return cb(error);
      }
      return cb(err);
    }
    const uploaderVersion = _.get(resp, ['versions', 'uploaderMinimum'], null);
    if (uploaderVersion !== null) {
      return cb(null, resp.versions);
    }
    return cb(new Error(format('Info response does not contain versions.uploaderMinimum.')));
  });
};

api.upload.accounts = (happyCb, sadCb) => {
  api.log(`GET /access/groups/${tidepool.getUserId()}`);
  tidepool.getViewableUsers(tidepool.getUserId(), (err, data) => {
    if (err) {
      return sadCb(err, err);
    }
    return happyCb(data, 'upload accounts found');
  });
};

function getUploadFunction(uploadType) {
  if (uploadType === 'dataservices') {
    return tidepool.addDataToDataset;
  }

  if (uploadType === 'jellyfish') {
    return tidepool.uploadDeviceDataForUser;
  }
  return null;
}

function buildError(error, datasetId) {
  const err = new Error('Uploading data to platform failed.');
  err.name = 'API Error';
  err.status = error.status;
  err.datasetId = datasetId;
  if (error.sessionToken) {
    err.sessionToken = crypto.createHash('md5').update(error.sessionToken).digest('hex');
  }
  if (error.meta && error.meta.trace) {
    err.requestTrace = error.meta.trace.request;
    err.sessionTrace = error.meta.trace.session;
  }

  api.log(JSON.stringify(error, null, '\t'));

  return err;
}

function createDatasetForUser(userId, info, callback) {
  const happy = (dataset) => callback(null, dataset);

  const sad = (err) => {
    api.log('platform create dataset failed:', err);
    const error = buildError(err);
    callback(error);
  };

  const getDeduplicator = () => {
    if (_.indexOf(info.deviceManufacturers, 'Animas') > -1) {
      return 'org.tidepool.deduplicator.device.truncate.dataset';
    }
    return 'org.tidepool.deduplicator.device.deactivate.hash';
  };

  api.log('createDataset for user id ', userId, info);

  // eslint-disable-next-line no-param-reassign
  info.deduplicator = {
    name: getDeduplicator(),
  };

  tidepool.createDatasetForUser(userId, info, (err, dataset) => {
    if (err) {
      return sad(err);
    }
    return happy(dataset);
  });
}

function finalizeDataset(datasetId, callback) {
  const happy = () => callback();

  const sad = (err) => {
    api.log('platform finalize dataset failed:', err);
    const error = buildError(err, datasetId);
    callback(error);
  };

  api.log('finalize dataset for dataset id ', datasetId);

  tidepool.finalizeDataset(datasetId, (err, result) => {
    if (err) {
      return sad(err, result);
    }
    return happy();
  });
}

function addDataToDataset(data, datasetId, blockIndex, uploadType, callback) {
  const recCount = data.length;
  const happy = () => callback(null, recCount);

  const sad = (error) => {
    api.log('addDataToDataset: checking failure details');
    if (error.status === 413 && data.length > 1) { // request entity too big
      // but we can split the request and try again
      const l = Math.floor(data.length / 2);
      const d1 = data.slice(0, l);
      const d2 = data.slice(l);
      async.mapSeries([d1, d2], addDataToDataset, (err, result) => {
        if (err) {
          return callback(err, 0);
        }
        return callback(null, result[0] + result[1]);
      });
      return;
    }
    if (error.responseJSON && error.responseJSON.errorCode && error.responseJSON.errorCode === 'duplicate') {
      api.log(error.responseJSON);
      callback('duplicate', error.responseJSON.index);
    } else {
      api.log('platform add data to dataset failed.');
      const err = buildError(error, datasetId);

      if (error.errors && error.errors.length > 0) {
        // eslint-disable-next-line no-restricted-syntax
        for (const i in error.errors) {
          if (error.errors[i].source) {
            const hpattern = /\/(\d+)\//;
            const toMatch = hpattern.exec(error.errors[i].source.pointer);
            if (toMatch[1]) {
              api.log('Offending record for error', i, ':', JSON.stringify(data[parseInt(toMatch[1], 10)], null, '\t'));
            }
          }
        }
      }

      callback(err);
    }
  };

  api.log(`addDataToDataset #${blockIndex}: using id ${datasetId}`);

  const uploadForUser = getUploadFunction(uploadType);
  uploadForUser(datasetId, data, (err, result) => {
    if (err) {
      return sad(err);
    }
    return happy(result);
  });
}

function searchForPeriod(dayMinute, periods) {
    var periodId = '';
    for (var i = 0; i < periods.length; i++) {
        var beginMinute = 60 * parseInt(periods[i].beginTime.split(':')[0]);
        beginMinute += parseInt(periods[i].beginTime.split(':')[1]);

        var endMinute = 60 * parseInt(periods[i].endTime.split(':')[0]);
        endMinute += parseInt(periods[i].endTime.split(':')[1]);

        if (beginMinute <= dayMinute && dayMinute <= endMinute) {
            periodId = periods[i].id;
            break;
        }
    }
    return periodId;
}

/*
 * process the data sending it to the platform in blocks and feed back
 * progress to the calling function
 * uploadType is the final argument (instead of the callback) so that existing calls to
 * api.upload.toPlatform don't have to be modified in every driver, and will default to
 * the jellyfish api
 */
api.upload.toPlatform = (data, sessionInfo, progress, groupId, cb, uploadType = 'jellyfish', devices) => {
  // uploadType can either be 'jellyfish' or 'dataservices'

    api.log(`attempting to upload ${data.length} device data records to ${uploadType} api`);
    const grouped = _.groupBy(data, 'type');
    // eslint-disable-next-line no-restricted-syntax
    for (const type in grouped) {
        if ({}.hasOwnProperty.call(grouped, type)) {
            api.log(grouped[type].length, 'records of type', type);
        }
    }
    async.series([getPersonalSensorList.bind(null, sessionInfo), getPeriodList], (err, results) => {

        if (err != null){
            api.log('upload.toPlatform: failed ', err);
            return cb(err);
        }

        const [params, periods] = results;
        var sensorAlreadyAssigned = params.isAlreadyAssignedToActualPatient;

        if (sensorAlreadyAssigned == false){
            var sensor = getSensorFromSessionInfo(sessionInfo);
            addOrUpdateSensorInServer(sensor);
            api.log('upload.toPlatform: all good');
            return cb(null, [1]);
        }
        var sensor = params.sensorSelected;
        var now = Date.now();

        sensor.lastConnection = now.valueOf();
        var lastUpdate = sensor.lastUpdate;
        var measureList = [];

        for (let i = 0; i < data.length; i++) {

            var typeId;
            var value;

            if (data[i].type == 'smbg') {
                typeId = "MEASURE_TYPE_BLOOD_SUGAR_LEVEL";
                value = data[i].value.toFixed(3);
            } else if (data[i].type == 'cbg') {
                typeId = "MEASURE_TYPE_INTERSTITIAL_BLOOD_SUGAR_LEVEL";
                value = data[i].value.toFixed(3);
            } else if (data[i].type == 'basal') {
                typeId = "MEASURE_TYPE_BASAL_INSULIN";
                value = data[i].rate.toFixed(3);
            } else if (data[i].type == 'bolus' && data[i].subType == 'normal') {
                typeId = "MEASURE_TYPE_RAPID_ACTING_INSULIN";
                value = data[i].normal.toFixed(3);
            } else if (data[i].type == 'bolus' && data[i].subType == 'square') {
                typeId = "MEASURE_TYPE_LONG_ACTING_INSULIN";
                value = data[i].extended.toFixed(3);
            } else if (data[i].type == 'bloodKetone') {
                typeId = "MEASURE_TYPE_BLOOD_KETONE";
                value = data[i].value.toFixed(3);
            } else {
                continue;
            }

            var eventDate = new Date(data[i].time);
            var eventDateMillis = new Date(data[i].time).valueOf();

            if (eventDateMillis > lastUpdate && eventDateMillis <= now) {
                var dayMinute = (eventDate.getHours() * 60) + eventDate.getMinutes();
                measureList.push(
                    {
                        "id": "MEASURE_" + eventDateMillis,
                        //"id": "MEASURE_" + 1650547339000,
                        "date": eventDateMillis,
                        //"date": 1650547339000,
                        "patientId": patient.id,
                        "typeId": typeId,
                        "value": parseFloat(value) + 0.0000001,
                        "period": searchForPeriod(dayMinute, periods),
                        "comment": "",
                        "commentIdList": ""
                    }
                );
            }
        }

        if (measureList.length == 0){
            addOrUpdateSensorInServer(sensor);
            api.log('upload.toPlatform: all good');
            return cb(null, [1]);
        }

        measureList.sort((x,y) => {return x.date - y.date});
        async.series([pushMeasure.bind(null, measureList)], (err, results) => {

            if (err != null){
                api.log('upload.toPlatform: failed ', err);
                return cb(err);
            }

            sensor.lastUpdate = measureList[measureList.length - 1].date;
            addOrUpdateSensorInServer(sensor);
            api.log('upload.toPlatform: all good');
            return cb(null, [1]);
        });
    });
};

api.getMostRecentUploadRecord = (userId, deviceId, cb) => {
    api.log(`GET /data_sets?deviceId=${deviceId}&size=1`);
    tidepool.getUploadRecordsForDevice(userId, deviceId, 1, (err, resp) => {
        if (err) {
            if (!navigator.onLine) {
                const error = new Error(ErrorMessages.E_OFFLINE);
                error.originalError = err;
                return cb(error);
            }
            return cb(err);
        }
        api.log('Upload record response:', resp);
        if (resp && resp.length > 0) {
            return cb(null, resp[0]);
        }

        // could not retrieve an upload record, so return null
        return cb(null, null);
    });
};

api.upload.blob = (blob, contentType, cb) => {
    api.log('POST /blobs');

    const digest = crypto.createHash('md5').update(blob).digest('base64');
    const blobObject = new Blob([blob], {type: contentType});

    tidepool.uploadBlobForUser(tidepool.getUserId(), blobObject, contentType, `MD5=${digest}`, (err, result) => {
        if (err) {
            return cb(err, null);
        }
        return cb(null, result);
    });
};

// ----- Metrics -----

api.metrics = {};

api.metrics.track = (eventName, properties) => {
    api.log(`GET /metrics/${window.encodeURIComponent(eventName)}`);
    //return tidepool.trackMetric(eventName, properties);
};

// ----- Server time -----
api.getTime = (cb) => {
    api.log('GET /time');
    tidepool.getTime((err, resp) => {
        if (err) {
            if (!navigator.onLine) {
                const error = new Error(ErrorMessages.E_OFFLINE);
                error.originalError = err;
                return cb(error);
            }
            return cb(err);
        }
        if (resp.data && resp.data.time) {
            return cb(null, resp.data.time);
        }
        // the response is not in the right format,
        // so we send nothing back
        return cb(null, null);
    });
};

// ----- Clinics -----

api.clinics = {};

api.clinics.getPatientsForClinic = (clinicId, options, cb) => tidepool.getPatientsForClinic(clinicId, options, cb);

api.clinics.createClinicCustodialAccount = (clinicId, patient, cb) => tidepool.createClinicCustodialAccount(clinicId, patient, cb);

api.clinics.updateClinicPatient = (clinicId, patientId, patient, cb) => tidepool.updateClinicPatient(clinicId, patientId, patient, cb);

api.clinics.getClinicsForClinician = (clinicianId, options, cb) => tidepool.getClinicsForClinician(clinicianId, options, cb);

// ----- Errors -----

api.errors = {};

api.errors.log = (error, message, properties) => {
    api.log('GET /errors');

    if (rollbar) {
        const extra = {};
        if (_.get(error, 'data.blobId', false)) {
            _.assign(extra, {blobId: error.data.blobId});
        }
        if (_.isError(error.originalError)) {
            _.assign(extra, {displayError: _.omit(error, ['originalError'])});
            // eslint-disable-next-line no-param-reassign
            error = error.originalError;
        }
        rollbar.error(error, extra);
    }
    return tidepool.logAppError(error.debug, message, properties);
};

module.exports = api;

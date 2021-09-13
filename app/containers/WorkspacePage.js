import React from 'react';
import { useDispatch, useSelector } from 'react-redux';
import map from 'lodash/map';

import * as metrics from '../constants/metrics';
import { pages } from '../constants/otherConstants';
import * as actionSources from '../constants/actionSources';
import actions from '../actions/';
import { remote } from 'electron';

const i18n = remote.getGlobal('i18n');

const { async, sync } = actions;

const styles = require('../../styles/components/WorkspacePage.module.less');

export const WorkspacePage = (props) => {
  const dispatch = useDispatch();
  const clinics = useSelector((state)=>state.clinics);
  const blipUrls = useSelector((state)=>state.blipUrls);

  const handleSwitchWorkspace = (clinic) => {
    dispatch(sync.selectClinic(clinic.id));
    dispatch(async.fetchPatientsForClinic(clinic.id));
    dispatch(
      async.setPage(pages.CLINIC_USER_SELECT, actionSources.USER, {
        metric: { eventName: metrics.CLINIC_SEARCH_DISPLAYED },
      })
    );
  };

  return (
    <div className={styles.wrap}>
      <div className={styles.wrapInner}>
        <div className={styles.headerWrap}>
          <div className={styles.header}>
            {i18n.t('Clinic Workspace')}
          </div>
        </div>
        <div className={styles.headerDetail}>
          {i18n.t('To manage your clinic workspaces and view patient invites')}, <a href={blipUrls.blipUrl} target="_blank">{i18n.t('login to your account in Tidepool Web')}</a>
        </div>
        <div className={styles.workspaceList}>
          {map(clinics,(clinic,i)=>
            <div className={styles.workspaceItem} key={clinic.id}>
              <div className={styles.clinicName}>{clinic.name}</div>
              <div className={styles.clinicSwitchButton} onClick={()=>handleSwitchWorkspace(clinic)}>{i18n.t('Go to Workspace')}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default WorkspacePage;
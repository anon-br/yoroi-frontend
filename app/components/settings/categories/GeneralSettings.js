// @flow
import React, { Component } from 'react';
import { observer } from 'mobx-react';
import classNames from 'classnames';
import { Select } from 'react-polymorph/lib/components/Select';
import { SelectSkin } from 'react-polymorph/lib/skins/simple/SelectSkin';
import { defineMessages, intlShape } from 'react-intl';
import ReactToolboxMobxForm from '../../../utils/ReactToolboxMobxForm';
import LocalizableError from '../../../i18n/LocalizableError';
import styles from './GeneralSettings.scss';
import type { ReactIntlMessage } from '../../../types/i18nTypes';
import FlagLabel from '../../widgets/FlagLabel';
import { tier1Languages } from '../../../config/languagesConfig';

const messages = defineMessages({
  languageSelectLabel: {
    id: 'settings.general.languageSelect.label',
    defaultMessage: '!!!Language',
  },
  languageSelectLabelInfo: {
    id: 'settings.general.languageSelect.labelInfo',
    defaultMessage: '!!!LanguageLabelInfo',
  },
  languageSelectInfo: {
    id: 'settings.general.languageSelect.info',
    defaultMessage: '!!!LanguageInfo',
  },
  languageSelectThanking: {
    id: 'settings.general.languageSelect.thanking',
    defaultMessage: '!!!Thanks to the following',
  },
  languageSelectContributors: {
    id: 'settings.general.languageSelect.contributors',
    defaultMessage: '!!!contributors',
  },
});

type Props = {
  languages: Array<{ value: string, label: ReactIntlMessage, svg: string }>,
  currentLocale: string,
  onSelectLanguage: Function,
  isSubmitting: boolean,
  error?: ?LocalizableError,
};

@observer
export default class GeneralSettings extends Component<Props> {
  static defaultProps = {
    error: undefined
  };

  static contextTypes = {
    intl: intlShape.isRequired,
  };

  selectLanguage = (values: { locale: string }) => {
    this.props.onSelectLanguage({ locale: values });
  };

  form = new ReactToolboxMobxForm({
    fields: {
      languageId: {
        label: this.context.intl.formatMessage(messages.languageSelectLabel),
        value: this.props.currentLocale,
      }
    }
  }, {
    options: {
      validateOnChange: false,
    },
  });

  render() {
    const { languages, isSubmitting, error } = this.props;
    const { intl } = this.context;
    const { form } = this;
    const languageId = form.$('languageId');
    const languageOptions = languages.map(language => ({
      value: language.value,
      label: intl.formatMessage(language.label),
      svg: language.svg
    }));
    const componentClassNames = classNames([styles.component, 'general']);
    const languageSelectClassNames = classNames([
      styles.language,
      isSubmitting ? styles.submitLanguageSpinner : null,
    ]);
    const contributors = intl.formatMessage(messages.languageSelectContributors);
    let contributorsMessage = ' ';
    if(contributors !== messages.languageSelectContributors.defaultMessage) {
      contributorsMessage = contributorsMessage + intl.formatMessage(messages.languageSelectThanking);
      contributorsMessage = contributorsMessage + contributors;
    }
    return (
      <div className={componentClassNames}>

        <Select
          className={languageSelectClassNames}
          options={languageOptions}
          {...languageId.bind()}
          onChange={this.selectLanguage}
          skin={SelectSkin}
          optionRenderer={option => (
            <FlagLabel svg={option.svg} label={option.label} />
          )}
        />
        {error && <p className={styles.error}>{error}</p>}

        {!tier1Languages.includes(languageId.value) &&
          <div className={styles.info}>
            <h1>{intl.formatMessage(messages.languageSelectLabelInfo)}</h1>
            <p>
              {intl.formatMessage(messages.languageSelectInfo)}
              {contributorsMessage}
            </p>
          </div>
        }

      </div>
    );
  }

}

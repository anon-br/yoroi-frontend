// @flow
import React, { Component } from 'react';
import { observer } from 'mobx-react';
import { computed } from 'mobx';
import type { Node } from 'react';
import type { InjectedOrGenerated } from '../../types/injectedPropsType';
import { PublicDeriver } from '../../api/ada/lib/storage/models/PublicDeriver/index';
import {
  MultiToken,
} from '../../api/common/lib/MultiToken';
import type { TokenInfoMap } from '../../stores/toplevel/TokenInfoStore';
import type { TokenRow } from '../../api/ada/lib/storage/database/primitives/tables';
import { genFormatTokenAmount, genLookupOrFail, getTokenIdentifierIfExists, getTokenStrictName } from '../../stores/stateless/tokenHelpers';
import { truncateToken } from '../../utils/formatters';
import AssetsPage from '../../components/wallet/assets/AssetsPage';

export type GeneratedData = typeof WalletAssetsPage.prototype.generated;

@observer
export default class WalletAssetsPage extends Component<InjectedOrGenerated<GeneratedData>> {

  render(): Node {
    const publicDeriver = this.generated.stores.wallets.selected;
    // Guard against potential null values
    if (!publicDeriver) throw new Error(`Active wallet required for ${nameof(WalletAssetsPage)}.`);
    const spendableBalance = this.generated.stores.transactions.getBalanceRequest.result
    const getTokenInfo= genLookupOrFail(this.generated.stores.tokenInfoStore.tokenInfo)

    const assetsList = (() => {
        if (spendableBalance == null) return [];
        return [
          ...spendableBalance.nonDefaultEntries(),
        ].map(entry => ({
          entry,
          info: getTokenInfo(entry),
        })).map(token => ({
          name: truncateToken(getTokenStrictName(token.info) ?? '-'),
          id: (getTokenIdentifierIfExists(token.info) ?? '-'),
          amount: genFormatTokenAmount(getTokenInfo)(token.entry)
        }));
      })();

    return <AssetsPage assetsList={assetsList} />
  }

  @computed get generated(): {|
    stores: {|
      tokenInfoStore: {|
        tokenInfo: TokenInfoMap,
        getDefaultTokenInfo: number => $ReadOnly<TokenRow>,
      |},
      transactions: {|
        getBalanceRequest: {|
          result: ?MultiToken,
        |},
      |},
      wallets: {| selected: null | PublicDeriver<> |}
    |}
    |} {
    if (this.props.generated !== undefined) {
      return this.props.generated;
    }
    if (this.props.stores == null) {
      throw new Error(`${nameof(WalletAssetsPage)} no way to generated props`);
    }
    const { stores } = this.props;
    return Object.freeze({
      stores: {
        wallets: {
          selected: stores.wallets.selected,
        },
        tokenInfoStore: {
          tokenInfo: stores.tokenInfoStore.tokenInfo,
          getDefaultTokenInfo: stores.tokenInfoStore.getDefaultTokenInfo,
        },
        transactions: {
          getBalanceRequest: (() => {
            if (stores.wallets.selected == null) return {
              result: undefined,
            };
            const { requests } = stores.transactions.getTxRequests(stores.wallets.selected);

            return {
              result: requests.getBalanceRequest.result,
            };
          })(),
        }
    } })
  }
};
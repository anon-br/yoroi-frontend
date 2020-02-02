// @flow

import { observable, action, reaction, runInAction } from 'mobx';
import { find } from 'lodash';
import Store from '../base/Store';
import {
  Logger,
  stringifyError,
} from '../../utils/logging';
import CachedRequest from '../lib/LocalizedCachedRequest';
import {
  PublicDeriver,
} from '../../api/ada/lib/storage/models/PublicDeriver/index';
import {
  asGetStakingKey,
} from '../../api/ada/lib/storage/models/PublicDeriver/traits';
import type {
  IGetStakingKey,
} from '../../api/ada/lib/storage/models/PublicDeriver/interfaces';
import {
  getDelegatedBalance,
  getCurrentDelegation,
} from '../../api/ada/lib/storage/bridge/delegationUtils';
import type {
  GetDelegatedBalanceFunc,
  GetCurrentDelegationFunc,
} from '../../api/ada/lib/storage/bridge/delegationUtils';
import environment from '../../environment';
import type {
  AccountStateSuccess,
  RemotePoolMetaSuccess,
  ReputationFunc,
  RewardTuple,
} from '../../api/ada/lib/state-fetch/types';
import LocalizableError from '../../i18n/LocalizableError';
import PublicDeriverWithCachedMeta from '../../domain/PublicDeriverWithCachedMeta';
import {
  genToRelativeSlotNumber,
  genTimeToSlot,
} from '../../api/ada/lib/storage/bridge/timeUtils';


type StakingKeyState = {|
  state: AccountStateSuccess,
  /**
    * Pool selected in the UI
    */
  selectedPool: number;
  /**
    * careful: there may be less entries in this map than # of pools in a certificate
    * I think you can use ratio stake to stake to the same stake pool multiple times
    */
  poolInfo: Map<string, RemotePoolMetaSuccess>
|};

type RewardHistoryForWallet = string => Promise<Array<RewardTuple>>;

export type DelegationRequests = {|
  publicDeriver: PublicDeriver<>,
  getDelegatedBalance: CachedRequest<GetDelegatedBalanceFunc>,
  getCurrentDelegation: CachedRequest<GetCurrentDelegationFunc>,
  rewardHistory: CachedRequest<RewardHistoryForWallet>,
  error: LocalizableError | any;
  stakingKeyState: void | StakingKeyState;
|};

export default class DelegationStore extends Store {

  @observable delegationRequests: Array<DelegationRequests> = [];

  @observable poolReputation: CachedRequest<ReputationFunc>
    = new CachedRequest<ReputationFunc>(() => {
      // we need to defer this call because the store may not be initialized yet
      // by the time this constructor is called
      const stateFetcher = this.stores.substores[environment.API].stateFetchStore.fetcher;
      return stateFetcher.getReputation();
    });

  _recalculateDelegationInfoDisposer: void => void = () => {};

  getRequests: PublicDeriver<> => void | DelegationRequests = (
    publicDeriver
  ) => {
    const foundRequest = find(this.delegationRequests, { publicDeriver });
    if (foundRequest) return foundRequest;

    return undefined; // can happen if the wallet is not a Shelley wallet
  }

  @action addObservedWallet: PublicDeriverWithCachedMeta => void = (
    publicDeriver
  ) => {
    const newObserved = {
      publicDeriver: publicDeriver.self,
      getDelegatedBalance: new CachedRequest<GetDelegatedBalanceFunc>(getDelegatedBalance),
      getCurrentDelegation: new CachedRequest<GetCurrentDelegationFunc>(getCurrentDelegation),
      rewardHistory: new CachedRequest<RewardHistoryForWallet>(async (address) => {
        // we need to defer this call because the store may not be initialized yet
        // by the time this constructor is called
        const stateFetcher = this.stores.substores[environment.API].stateFetchStore.fetcher;
        const result = await stateFetcher.getRewardHistory({ addresses: [address] });
        return result[address] ?? [];
      }),
      stakingKeyState: undefined,
      error: undefined,
    };
    this.delegationRequests.push(newObserved);
  }

  setup(): void {
    super.setup();
    this.reset();
    this._startWatch();
    this.registerReactions([
      this._loadPoolReputation,
    ]);
  }

  refreshDelegation: PublicDeriverWithCachedMeta => Promise<void> = async (
    publicDeriver
  ) => {
    const delegationRequest = this.getRequests(publicDeriver.self);
    if (delegationRequest == null) return;

    try {
      delegationRequest.getDelegatedBalance.reset();
      delegationRequest.getCurrentDelegation.reset();
      runInAction(() => {
        delegationRequest.error = undefined;
        delegationRequest.stakingKeyState = undefined;
      });

      const withStakingKey = asGetStakingKey(publicDeriver.self);
      if (withStakingKey == null) {
        throw new Error(`${nameof(this.refreshDelegation)} missing staking key functionality`);
      }

      const stakingKeyResp = await withStakingKey.getStakingKey();

      const accountStateCalcs = (async () => {
        try {
          const stateFetcher = this.stores.substores[environment.API].stateFetchStore.fetcher;
          const accountStateResp = await stateFetcher.getAccountState({
            addresses: [stakingKeyResp.addr.Hash],
          });
          const stateForStakingKey = accountStateResp[stakingKeyResp.addr.Hash];
          if (!stateForStakingKey.delegation) {
            return runInAction(() => {
              delegationRequest.stakingKeyState = undefined;
              throw new Error(`${nameof(this.refreshDelegation)} stake key invalid - ${stateForStakingKey.comment}`);
            });
          }
          const delegatedBalance = delegationRequest.getDelegatedBalance.execute({
            publicDeriver: withStakingKey,
            accountState: stateForStakingKey,
            stakingAddress: stakingKeyResp.addr.Hash,
          }).promise;
          if (delegatedBalance == null) throw new Error('Should never happen');

          const poolInfoRequest = this._getPoolInfo({ delegationRequest, stateForStakingKey });
          return await Promise.all([
            delegatedBalance,
            poolInfoRequest,
          ]);
        } catch (e) {
          runInAction(() => {
            delegationRequest.error = e;
          });
        }
      })();

      const delegationHistory = this._getDelegationHistory({
        publicDeriver: withStakingKey,
        stakingKeyAddressId: stakingKeyResp.addr.AddressId,
        delegationRequest,
      });

      const rewardHistory = delegationRequest.rewardHistory.execute(
        stakingKeyResp.addr.Hash
      ).promise;

      await Promise.all([
        accountStateCalcs,
        delegationHistory,
        rewardHistory,
      ]);
    } catch (e) {
      Logger.error(`${nameof(DelegationStore)}::${nameof(this.refreshDelegation)} error: ` + stringifyError(e));
    }
  }

  _getPoolInfo: {|
    delegationRequest: DelegationRequests,
    stateForStakingKey: AccountStateSuccess,
  |} => Promise<void> = async (request) => {
    const stateFetcher = this.stores.substores[environment.API].stateFetchStore.fetcher;
    const poolInfoResp = await stateFetcher.getPoolInfo({
      ids: request.stateForStakingKey.delegation.pools.map(delegation => delegation[0]),
    });
    const meta = new Map(request.stateForStakingKey.delegation.pools.map(delegation => {
      const info = poolInfoResp[delegation[0]];
      if (!info.history) {
        return runInAction(() => {
          request.delegationRequest.stakingKeyState = undefined;
          throw new Error(`${nameof(this.refreshDelegation)} pool info missing ${info.error}`);
        });
      }
      return [delegation[0], info];
    }));
    runInAction(() => {
      request.delegationRequest.stakingKeyState = {
        state: request.stateForStakingKey,
        selectedPool: 0,
        poolInfo: meta,
      };
    });
  }

  _getDelegationHistory: {|
    publicDeriver: PublicDeriver<> & IGetStakingKey,
    stakingKeyAddressId: number,
    delegationRequest: DelegationRequests,
  |} => Promise<void> = async (request) => {
    const toRelativeSlotNumber = await genToRelativeSlotNumber();
    const timeToSlot = await genTimeToSlot();
    const currentEpoch = toRelativeSlotNumber(
      timeToSlot({
        time: new Date(),
      }).slot
    ).epoch;

    const currentDelegation = request.delegationRequest.getCurrentDelegation.execute({
      publicDeriver: request.publicDeriver,
      stakingKeyAddressId: request.stakingKeyAddressId,
      toRelativeSlotNumber,
      currentEpoch,
    }).promise;
    if (currentDelegation == null) throw new Error('Should never happen');
  }

  @action.bound
  _startWatch: void => void = () => {
    this._recalculateDelegationInfoDisposer = reaction(
      () => [
        this.stores.substores.ada.wallets.selected,
        // num tx sync changed => valid inputs may have changed
        this.stores.substores.ada.transactions.totalAvailable,
        // need to recalculate when there are no more pending transactions
        this.stores.substores.ada.transactions.hasAnyPending,
        // if query failed due to server issue, need to re-query when it comes back online
        this.stores.substores.ada.serverConnectionStore.checkAdaServerStatus,
        // reward grows every epoch so we have to refresh
        this.stores.substores.ada.time.currentTime?.currentEpoch,
      ],
      // $FlowFixMe error in mobx types
      async () => {
        const selected = this.stores.substores.ada.wallets.selected;
        if (selected == null) return;
        await this.refreshDelegation(selected);
      },
    );
  }

  @action.bound
  reset(): void {
    this._recalculateDelegationInfoDisposer();
    this._recalculateDelegationInfoDisposer = () => {};
    this.delegationRequests = [];
  }

  _loadPoolReputation: void => Promise<void> = async () => {
    await this.poolReputation.execute();
  }
}

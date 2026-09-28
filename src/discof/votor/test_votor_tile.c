#define FD_TILE_TEST 1
#include "fd_votor_tile.c"

#define TEST_VOTER_MAX (4UL)

static ag_epoch_info_t epoch_info_mem;

static void
build_stakes( fd_vote_stake_weight_t * out,
              ulong                    cnt,
              ulong                    base ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &out[i], 0, sizeof(fd_vote_stake_weight_t) );
    out[i].stake           = base + i;
    out[i].id_key.uc  [ 0 ] = (uchar)( i + 1UL );
    out[i].vote_key.uc[ 0 ] = (uchar)( i + 0x80UL );

    fd_bls_sec_t sec; memset( &sec, (int)( i*7UL + 1UL ), FD_BLS_SEC_SZ );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &sec, &pub );
    blst_p1_compress( out[i].bls_key, &pub );
  }
}

static void
test_rank_voters_resets_total_stake( void ) {
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  ag_epoch_info_t *      epoch_info = &epoch_info_mem;

  build_stakes( stakes, 3UL, 10UL );
  FD_TEST( rank_voters( epoch_info, stakes, 3UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==3UL  );
  FD_TEST( epoch_info->total_stake  ==33UL );

  build_stakes( stakes, 2UL, 5UL );
  FD_TEST( rank_voters( epoch_info, stakes, 2UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==2UL  );
  FD_TEST( epoch_info->total_stake  ==11UL );
}

static void
unexpected_sign( void *         ctx,
                 fd_bls_sig_t * sig,
                 uchar const *  msg,
                 ulong          msg_sz ) {
  (void)ctx; (void)sig; (void)msg; (void)msg_sz;
  FD_LOG_ERR(( "adopting an empty history must not sign a vote" ));
}

static void
test_input_link_indices( void ) {
  static fd_topo_t topo;
  fd_topo_tile_t * tile = &topo.tiles[ 0 ];
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "votor_inputs", 0UL );
  FD_TEST( wksp );
  topo.workspaces[ 0 ].wksp = wksp;
  topo.objs[ 0 ].wksp_id    = 0UL;
  char const * names[] = { "replay_out", "replay_epoch", "gossip_out", "ipecho_out", "net_votor", "sign_votor", "failov_votor" };
  tile->in_cnt = sizeof(names)/sizeof(names[0]);
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo.links[ i ];
    fd_cstr_ncpy( link->name, names[ i ], sizeof(link->name) );
    link->mtu = AG_HIST_SER_MAX;
    ulong data_sz = fd_dcache_req_data_sz( link->mtu, 4UL, 1UL, 1 );
    void * mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
    FD_TEST( mem );
    link->dcache = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
    FD_TEST( link->dcache );
    tile->in_link_id[ i ]   = i;
    tile->in_link_poll[ i ] = strcmp( names[ i ], "sign_votor" )!=0;
  }

  static fd_votor_tile_t ctx_mem[ 1 ];
  static uchar votor_mem[ 1UL<<20 ] __attribute__((aligned(128)));
  fd_votor_tile_t * ctx = ctx_mem;
  FD_TEST( ag_votor_footprint( 16UL )<=sizeof(votor_mem) );
  ctx->votor = ag_votor_join( ag_votor_new( votor_mem, 16UL, 42UL ) );
  FD_TEST( ctx->votor );
  /* Empty-history adoption does not sign, but requires initialized consensus. */
  ag_votor_init( ctx->votor, 0UL, 0L, 400000000L, 1U, unexpected_sign, NULL );
  ctx->init = 1;
  ctx->failover_enabled = 1;

  static uchar reply_mem[ 512 ] __attribute__((aligned(FD_CHUNK_SZ)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[] = { mcache };
  ulong seqs[] = { 0UL }, depths[] = { 8UL };
  ulong cr_avail = 64UL, min_cr_avail = 64UL;
  int reliable = 0;
  fd_stem_context_t stem[ 1 ] = {{
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  }};
  ctx->failov_out_idx = 0UL;
  ctx->failov_out_mem = reply_mem;
  ctx->failov_out_wmark = 4UL;
  init_input_links( ctx, &topo, tile );

  /* Stem skips the synchronous sign response link when numbering callbacks. */
  ulong callback_idx = 0UL;
  for( ulong i=0UL; i<6UL; i++ ) callback_idx += !!tile->in_link_poll[ i ];
  FD_TEST( callback_idx==5UL );
  fd_topo_link_t const * link = &topo.links[ 6 ];
  FD_STORE( ulong, link->dcache, 9UL );
  ulong chunk = fd_dcache_compact_chunk0( wksp, link->dcache );
  FD_TEST( !before_frag( ctx, callback_idx, 0UL, 901UL ) );
  during_frag( ctx, callback_idx, 0UL, 901UL, chunk, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL );
  after_frag( ctx, callback_idx, 0UL, 901UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  FD_TEST( seqs[0]==1UL && mcache[0].sig==901UL && mcache[0].sz==sizeof(fd_votor_adopt_result_t) );
  fd_votor_adopt_result_t const * reply = fd_chunk_to_laddr_const( reply_mem, mcache[0].chunk );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_SUCCESS && reply->vote_bound==9UL );
  FD_TEST( ctx->failover_hist_adopted );
  FD_TEST( ctx->in_kind[ callback_idx ]==IN_KIND_FAILOV );
  FD_TEST( ctx->in[ callback_idx ].chunk0==chunk && ctx->in[ callback_idx ].mtu==link->mtu );

  /* A request without a bound is refused and preserves the earlier bound. */
  ctx->failover_hist_adopted = 0;
  FD_STORE( ulong, link->dcache, ULONG_MAX );
  during_frag( ctx, callback_idx, 1UL, 902UL, chunk, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL );
  after_frag( ctx, callback_idx, 1UL, 902UL, FD_VOTOR_ADOPT_EMPTY_SZ, 0UL, 0UL, stem );
  FD_TEST( seqs[0]==2UL && mcache[1].sig==902UL && mcache[1].sz==sizeof(fd_votor_adopt_result_t) );
  reply = fd_chunk_to_laddr_const( reply_mem, mcache[1].chunk );
  FD_TEST( reply->result==FD_VOTOR_ADOPT_ERR_INVALID && !ctx->failover_hist_adopted );
  FD_TEST( ag_votor_vote_bound( ctx->votor )==9UL );

  ag_votor_delete( ag_votor_leave( ctx->votor ) );
  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass: production input initialization routes adoption past the unpolled signer link" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_rank_voters_resets_total_stake();
  test_input_link_indices();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

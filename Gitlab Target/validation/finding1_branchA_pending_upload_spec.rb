# NOT EXECUTED IN THIS SESSION -- no Ruby interpreter, Bundler, database, or GitLab
# instance was available in this environment (see VALIDATION_01.md). This file is
# the exact regression test that would need to run against the real
# `ObjectStorage::Concern` / `ObjectStorage::PendingDirectUpload` classes (inside the
# actual GitLab test suite, with its Rails environment and DB loaded) to resolve the
# one open question in Finding 1 that this session's pure-Python tests could not
# reach: does `ObjectStorage::PendingDirectUpload.exists?(storage_location_identifier,
# remote_object_id)` bind a pending upload to the specific request/user/model that
# created it, or does it only prove "a pending upload with this exact id exists
# somewhere in this storage location, created by anyone"?
#
# How to run this for real (not done here):
#   1. Clone gitlab-org/gitlab, `bundle install`, set up the GDK test DB.
#   2. Save this file as spec/lib/object_storage_remote_id_ownership_spec.rb
#   3. bundle exec rspec spec/lib/object_storage_remote_id_ownership_spec.rb
#
# rubocop:disable all -- exploratory spec, not part of the real suite

require 'spec_helper'

RSpec.describe 'Finding 1 branch A: PendingDirectUpload ownership binding', feature_category: :shared do
  # Uses whichever concrete uploader class in the real app actually calls
  # ObjectStorage::Concern#cache! with use_final_store_path: true (an uploader that
  # goes through the "final store path" direct-upload flow, e.g. Ci::JobArtifactUploader
  # or similar -- the exact class was not confirmed in source review and would need
  # to be identified from the real codebase before this spec can run).
  let(:uploader_class) { raise 'fill in the real uploader class here before running' }

  let(:legitimate_model)  { create(:project) } # the model the id was ACTUALLY issued for
  let(:attacker_model)    { create(:project) } # a second, unrelated model/context

  it 'proves whether a remote_id issued for one model/request can be redeemed by a different one' do
    # 1. Simulate the legitimate flow: ask for a final-store-path direct upload,
    #    exactly as workhorse_remote_upload_options(use_final_store_path: true) does,
    #    which calls prepare_pending_direct_upload(id) -> creates a PendingDirectUpload row.
    root_hash = legitimate_model.id # or whatever root_hash the real final_store_path_config uses
    id = uploader_class.generate_final_store_path(root_hash: root_hash)
    uploader_class.prepare_pending_direct_upload(id)

    # 2. Attempt to redeem that SAME id from an uploader instantiated against a
    #    DIFFERENT model/container than the one it was generated for.
    attacker_uploader = uploader_class.new(attacker_model)
    uploaded_file = UploadedFile.new(nil, filename: 'exfiltrated.bin', remote_id: id, size: 123)

    result = nil
    raised = nil
    begin
      result = attacker_uploader.cache!(uploaded_file)
    rescue StandardError => e
      raised = e
    end

    # THE QUESTION THIS SPEC ANSWERS:
    #   - If this succeeds (no error, `result` is a valid cached file object) even
    #     though `attacker_model` never legitimately requested this specific `id`,
    #     that CONFIRMS Finding 1: the pending-upload existence check is a bare
    #     existence check, not an ownership check, and cross-model/cross-request
    #     object adoption is possible for anyone who can supply a valid (but not
    #     self-issued) id.
    #   - If this raises (e.g. a "not authorized for this model" error, or the
    #     pending upload record itself carries a model/user reference that is
    #     checked and mismatches), that DISPROVES Finding 1's branch-A concern --
    #     the ownership binding exists and this finding should be downgraded to
    #     FALSE POSITIVE for branch A specifically.
    #
    # Neither outcome was observed in this session; this spec is provided as the
    # concrete artifact needed to resolve it, not as evidence either way.
    expect([result.present?, raised.present?]).to satisfy('exactly one of these should be true, and whichever one is true resolves the finding') { |arr| arr.count(true) == 1 }
  end
end

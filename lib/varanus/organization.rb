# frozen_string_literal: true

# A connection to the Organization API
class Varanus::Organization < Varanus::RestResource
  # Return info on organization.
  def info id
    get("organization/v1/#{id}")
  end

  def list
    get('organization/v1')
  end
end

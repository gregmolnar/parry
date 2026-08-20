# frozen_string_literal: true

module Parry
  class RulesController < ApplicationController
    before_action :set_rule, only: [:edit, :update, :destroy]

    def index
      @rules = Parry.store.all
    end

    def new
      @rule = Rule.new(kind: allowed_kind(params[:kind]))
    end

    def create
      @rule = Rule.new(rule_params)

      if Parry.store.save(@rule)
        Parry.adapter.sync!(force: true)
        redirect_to rules_path, notice: "Rule created."
      else
        render :new, status: :unprocessable_entity
      end
    end

    def edit
    end

    def update
      @rule.assign_attributes(rule_params)

      if Parry.store.save(@rule)
        Parry.adapter.sync!(force: true)
        redirect_to rules_path, notice: "Rule updated."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    def export
      send_data RuleTransfer.export_json,
        filename: RuleTransfer.filename,
        type: "application/json",
        disposition: "attachment"
    end

    def import
    end

    def perform_import
      @result = import_result

      if @result.ok?
        Parry.adapter.sync!(force: true)
        redirect_to rules_path, notice: import_notice(@result)
      else
        render :import, status: :unprocessable_entity
      end
    end

    def destroy
      Parry.store.delete(@rule.id)
      Parry.adapter.sync!(force: true)
      redirect_to rules_path, notice: "Rule deleted."
    end

    private

    def import_result
      payload = import_payload

      if payload.blank?
        return RuleTransfer::Result.new(
          imported: 0,
          errors: ["Choose a file to import, or paste one in."],
          replaced: false
        )
      end

      RuleTransfer.import(payload, replace: params[:mode] == "replace")
    end

    def import_payload
      file = params[:file]
      return file.read(RuleTransfer::MAX_BYTES + 1).to_s if file.respond_to?(:read)

      params[:pasted].to_s
    end

    def import_notice(result)
      counted = "#{result.imported} #{"rule".pluralize(result.imported)}"

      result.replaced? ? "Replaced every rule with the #{counted} from the file." : "Imported #{counted}."
    end

    def set_rule
      @rule = Parry.store.find(params[:id])
      redirect_to rules_path, alert: "Rule not found." unless @rule
    end

    def rule_params
      params.require(:rule).permit(:kind, :value, :name, :limit, :period, :path, :path_match).to_h.symbolize_keys
    end

    def allowed_kind(kind)
      Rule::KINDS.include?(kind) ? kind : "honeypot"
    end
  end
end
